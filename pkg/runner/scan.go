/*
Package runner 单目标扫描流程（合并基础信息探测 + 指纹规则匹配）。

所有扫描方法都挂在 *Runner 上，资源句柄（FingerStore / RulePool / CacheManager /
HostRateLimiter / HTTPClient）全部通过 Runner 字段访问，不依赖任何包级状态。
*/
package runner

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanTarget 对单目标执行完整指纹识别。
//
// 流程：
//  1. 获取实例共享的目标并发名额
//  2. 对 HTTP 规则执行探活，提取标题 / 证书 / Server / ICP / Wappalyzer
//  3. warmUpRequestCache：把基础请求 / 响应写入缓存供后续规则复用
//  4. executeFingerprintMatching：把所有适用指纹提交到规则池并发评估
//  5. 清理本目标的缓存条目
func (r *Runner) ScanTarget(ctx context.Context, target string) (*TargetResult, error) {
	ctx = logger.WithContext(ctx, r.log)
	ctx, done, err := r.life.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}
	timeout := r.requestTimeout()

	result := newTargetResult(target)
	cache := r.cache.newScope()
	defer cache.clearScope()
	snap := r.store.executionSnapshot()
	ctx = cel.WithResponseCache(ctx)
	// 一次扫描一个 Cookie 会话：入口、规则请求与页面资源共用，扫描结束即释放。
	ctx = network.WithCookieJar(ctx)
	var earlier []*scanPage
	hasHTTP := false
	for _, entry := range snap {
		if entry.finger.IsHTTPType() {
			hasHTTP = true
			break
		}
	}
	if hasHTTP {
		base, err := r.getBaseInfo(ctx, target, timeout)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			// 独立 TCP/UDP 规则不依赖 HTTP 探活，混合库中的 HTTP 失败不能将其排除。
			var transportRules []fingerExecutionPlan
			for _, entry := range snap {
				if !entry.finger.IsHTTPType() {
					transportRules = append(transportRules, entry)
				}
			}
			if len(transportRules) == 0 {
				return nil, err
			}
			snap = transportRules
			r.log.Debug("目标 %s HTTP 探测失败，继续执行独立传输协议规则: %v", target, err)
		} else {
			r.applyBaseInfo(result, base)
			earlier = r.warmUpRequestCache(result, base, cache)
		}
	}

	if len(snap) == 0 {
		return result, nil
	}

	baseInfo := &BaseInfo{
		Title:      result.Title,
		Server:     result.Server,
		StatusCode: result.StatusCode,
		request:    result.LastRequest,
		response:   &proto.Response{Status: result.StatusCode, Url: &proto.UrlType{}},
		cache:      cache,
		rootTarget: result.URL,
		rootURL:    common.ParseTarget(result.URL, "/"),
		earlier:    earlier,
	}
	if baseInfo.request == nil {
		// HTTP 探测失败或整库只有 TCP/UDP 规则：合成只含地址的请求供 set 块求值。
		baseInfo.request = finger.TargetRequest(result.URL)
	}
	result.Matches = r.executeFingerprintMatching(ctx, result.URL, baseInfo, timeout, snap)
	return result, ctx.Err()
}

// GetBaseInfo 仅获取目标基础信息（不跑指纹）。
func (r *Runner) GetBaseInfo(ctx context.Context, target string) (*BaseInfoResponse, error) {
	ctx = logger.WithContext(ctx, r.log)
	ctx, done, err := r.life.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	return r.getBaseInfo(ctx, target, r.requestTimeout())
}

// requestTimeout 返回请求超时；未配置时默认 5 秒。
func (r *Runner) requestTimeout() time.Duration {
	if r.cfg.Timeout > 0 {
		return r.cfg.Timeout
	}
	return 5 * time.Second
}

func newTargetResult(target string) *TargetResult {
	return &TargetResult{
		URL:        target,
		StatusCode: 0,
		Title:      "",
		Server:     types.EmptyServerInfo(),
		Matches:    make([]*FingerMatch, 0, 10),
		Wappalyzer: nil,
	}
}

func (r *Runner) applyBaseInfo(result *TargetResult, base *BaseInfoResponse) {
	result.StatusCode = base.StatusCode
	result.Title = base.Title
	result.Server = base.Server
	result.Wappalyzer = base.Wappalyzer
	result.URL = base.Url
	result.ICP = base.ICP
	result.Certs = base.Certs
	result.FinalURL = base.FinalURL
	result.RedirectTo = base.RedirectTo
	result.Redirects = base.Redirects
}

// executeFingerprintMatching 并发评估当前指纹库的所有规则。
func (r *Runner) executeFingerprintMatching(ctx context.Context, target string, baseInfo *BaseInfo, timeout time.Duration, snap []fingerExecutionPlan) []*FingerMatch {
	if r.pool == nil || r.pool.IsClosed() {
		r.log.Error("规则池未初始化")
		return []*FingerMatch{}
	}
	if len(snap) == 0 {
		return []*FingerMatch{}
	}

	resultChan := make(chan *FingerMatch, calculateResultBuffer(len(snap)))

	matches := make([]*FingerMatch, 0, len(snap)/4+1)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for m := range resultChan {
			if m != nil && m.Result {
				matches = append(matches, m)
			}
		}
	}()

	activeWorkers := r.pool.CurrentWorkers()
	pipelineLimit := activeWorkers * 2
	if pipelineLimit < 1 {
		pipelineLimit = 1
	}
	limiter := make(chan struct{}, pipelineLimit)
	doneHook := func() { <-limiter }
	batchSize := min(ruleBatchSize, pipelineLimit)
	root, cachedRoot := baseInfo.cache.cache.GetIfPresent(baseInfo.cache.requestKey(common.RemoveTrailingSlash(baseInfo.rootURL), "GET", true))
	cachedRoot = cachedRoot && root != nil && root.Request != nil && root.Response != nil
	var batch *ruleBatch

	startTime := time.Now()
	var submitted int64
	var pruned int64
	var wg sync.WaitGroup
	flushBatch := func() {
		if batch == nil {
			return
		}
		count := batch.count
		if err := r.pool.submitBatch(batch); err != nil {
			for _, task := range batch.tasks[:count] {
				finishRuleTask(task)
			}
			releaseRuleBatch(batch)
		} else {
			submitted += int64(count)
		}
		batch = nil
	}

loop:
	for _, entry := range snap {
		fg := entry.finger
		if fg == nil {
			pruned++
			continue
		}
		select {
		case limiter <- struct{}{}:
		case <-ctx.Done():
			break loop
		}

		wg.Add(1)
		task := acquireRuleTask()
		task.Ctx = ctx
		task.Target = target
		task.Finger = fg
		task.prepared = entry.prepared
		task.BaseInfo = baseInfo
		task.Proxy = r.cfg.Proxy
		task.Timeout = timeout
		task.ResultChan = resultChan
		task.WaitGroup = &wg
		task.DoneHook = doneHook
		if cachedRoot && entry.cacheOnly {
			if batch == nil {
				batch = acquireRuleBatch()
			}
			batch.tasks[batch.count] = task
			batch.count++
			if batch.count == batchSize {
				flushBatch()
			}
			continue
		}

		// 规则池不限制阻塞提交数，Submit 会排队等待空闲 worker；返回错误只意味着规则池已关闭。
		if err := r.pool.Submit(task); err != nil {
			r.log.Debug("规则池已关闭，放弃提交指纹任务: %s, 错误: %v", fg.Id, err)
			wg.Done()
			<-limiter
			releaseRuleTask(task)
			continue
		}
		submitted++
	}
	flushBatch()

	if pruned > 0 {
		r.log.Debug("目标 %s 剪枝跳过 %d 条不适用规则", target, pruned)
	}

	wg.Wait()
	close(resultChan)
	collectorWG.Wait()

	// 规则并发完成顺序不确定，按指纹 ID 排序使同一目标的命中结果稳定可复现。
	slices.SortFunc(matches, func(a, b *FingerMatch) int {
		return strings.Compare(a.Finger.Id, b.Finger.Id)
	})

	r.log.Debug("目标 %s 指纹识别完成，耗时: %v, 匹配数量: %d/%d, 实际任务数: %d",
		target, time.Since(startTime), len(matches), len(snap), submitted)
	return matches
}

// sendFingerMatch 将匹配结果写入 channel；阻塞直至写入成功，或 ctx 取消时释放 m。
func sendFingerMatch(ctx context.Context, ch chan<- *FingerMatch, m *FingerMatch) {
	if m == nil || ch == nil {
		return
	}
	select {
	case ch <- m:
	case <-ctx.Done():
		releaseFingerMatch(m)
	}
}

// buildHTTPOptions 根据 Runner 配置构造 HTTP 请求选项。
func (r *Runner) buildHTTPOptions(timeout time.Duration, followRedirects bool) network.OptionsRequest {
	opts := network.OptionsRequest{
		Proxy:              r.cfg.Proxy,
		Timeout:            timeout,
		FollowRedirects:    followRedirects,
		InsecureSkipVerify: r.cfg.InsecureSkipVerify,
	}
	// cfg 在构造期复制，随后只读；规则覆盖头在 SendRequest 中单独复制。
	opts.CustomHeaders = r.cfg.CustomHeaders
	return opts
}

// processRuleTask 单个规则任务的执行体（由 RulePool handler 调用）。
func (r *Runner) processRuleTask(task *RuleTask) {
	result, err := r.evaluateFingerprint(task.Ctx, task.Finger, task.Target, task.BaseInfo, task.Proxy, task.Timeout, task.prepared)
	if err != nil {
		releaseFingerMatch(result)
		r.log.Debug("规则 %s 执行失败: %v", task.Finger.Id, err)
		return
	}
	if result != nil && result.Result {
		sendFingerMatch(task.Ctx, task.ResultChan, result)
	} else {
		releaseFingerMatch(result)
	}
}

// evaluateFingerprint 评估单条指纹。
//
// 根路径规则默认匹配入口跳转链的最后一页。未命中且链上还有更早的页面（入口的
// 30x 响应、跳转壳）时，依次把它们当作根路径响应重新评估，任一页满足即命中：
// 跳转链上的每个响应都是该资产的指纹素材。
func (r *Runner) evaluateFingerprint(ctx context.Context, fg *finger.Finger, target string, baseInfo *BaseInfo, proxy string, timeout time.Duration, plan *cel.PreparedLibrary) (*FingerMatch, error) {
	match, err := r.evaluateFingerprintOn(ctx, fg, target, baseInfo, timeout, plan, nil)
	if match != nil || err != nil || len(baseInfo.earlier) == 0 || !matchesEntryPage(fg) {
		return match, err
	}
	for _, page := range baseInfo.earlier {
		if match, err = r.evaluateFingerprintOn(ctx, fg, target, baseInfo, timeout, plan, page); match != nil || err != nil {
			break
		}
	}
	return match, err
}

// isPageRule 判断规则请求是否就是"跟随跳转地请求某个地址"，即入口页所代表的请求。
func isPageRule(req finger.RuleRequest) bool {
	return req.Method == "GET" && (req.Type == "" || req.Type == common.HttpType) && len(req.Headers) == 0 && req.Body == "" && req.Raw == "" && req.ShouldFollowRedirects()
}

// matchesEntryPage 判断指纹是否含有匹配入口页的规则；没有时换页重评结果不变。
func matchesEntryPage(fg *finger.Finger) bool {
	for _, rule := range fg.Rules {
		if IsEntryPageRule(rule.Value.Request) {
			return true
		}
	}
	return false
}

// evaluateFingerprintOn 评估单条指纹：CEL 求值 + 缓存命中 / 写入。
// page 非 nil 时，匹配入口页的规则改用该页的响应。
func (r *Runner) evaluateFingerprintOn(ctx context.Context, fg *finger.Finger, target string, baseInfo *BaseInfo, timeout time.Duration, plan *cel.PreparedLibrary, page *scanPage) (*FingerMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	customLib := acquireLibrary(plan)
	defer releaseLibrary(customLib)
	customLib.SetContext(ctx)
	customLib.SetRequestOptions(r.httpClient, r.buildHTTPOptions(timeout, true))
	customLib.SetReverseConfig(r.cfg.Reverse)
	customLib.SetEvidenceEnabled(r.cfg.CaptureEvidence)
	cache := baseInfo.cache
	varMap := acquireVarMap()
	defer releaseVarMap(varMap)

	varMap["title"] = baseInfo.Title
	varMap["server"] = baseInfo.Server
	// 前置请求 / 响应只读，规则请求会替换 map 中的引用，不修改共享消息。
	// request 必须在 set 求值前就位，否则 `request.url.host` 这类变量会求值
	// 失败并被 IsFuzzSet 当成字面量写回（TCP/UDP 规则的 host 由它拼装）。
	varMap["request"] = baseInfo.request
	varMap["response"] = baseInfo.response

	if len(fg.Set) > 0 {
		finger.IsFuzzSet(fg.Set, varMap, customLib)
	}
	if len(fg.Payloads.Payloads) > 0 {
		finger.IsFuzzSet(fg.Payloads.Payloads, varMap, customLib)
	}

	// 预注册所有规则结果函数到 customLib，后续按规则键更新底层 bool 值即可，
	// 整个 fingerprint 评估周期内 base.Extend 只发生一次。
	if plan == nil && len(fg.Rules) > 0 {
		ruleKeys := make([]string, 0, len(fg.Rules))
		for _, rule := range fg.Rules {
			if rule.Key != "" {
				ruleKeys = append(ruleKeys, rule.Key)
			}
		}
		customLib.PreRegisterRuleFunctions(ruleKeys)
	}

	var matchedRules []SubRuleMatch
	var versions []string
	versionConflict := false
	detailsTruncated := false
	for _, rule := range fg.Rules {
		reqCopy := rule.Value.Request
		reqCopy.Path = finger.SetVariableMap(strings.TrimSpace(reqCopy.Path), varMap)
		urlStr := baseInfo.rootURL
		if reqCopy.Path != "/" || baseInfo.rootTarget != target {
			urlStr = common.ParseTarget(target, reqCopy.Path)
		}

		ruleCopy := rule
		ruleCopy.Value.Request = reqCopy

		var hit bool
		var cachedReq *proto.Request
		var cachedResp *proto.Response
		if page != nil && urlStr == baseInfo.rootURL && isPageRule(reqCopy) {
			hit, cachedReq, cachedResp, urlStr = true, page.request, page.response, page.url
		} else {
			hit, cachedReq, cachedResp = cache.ShouldUseCache(ruleCopy, urlStr)
		}
		if logger.IsDebugEnabled(r.log) {
			r.log.Debug("%s 规则 %s 是否使用缓存：%t", target, ruleCopy.Key, hit)
		}

		if hit && cachedReq != nil && cachedResp != nil {
			varMap["request"] = cachedReq
			varMap["response"] = cachedResp
		} else {
			ruleOpts := r.buildHTTPOptions(timeout, reqCopy.ShouldFollowRedirects())
			var err error
			// 仅合并同次扫描内本就允许缓存的普通 GET；请求状态、取消和配置不跨扫描共享。
			if strings.EqualFold(reqCopy.Method, "GET") && len(reqCopy.Headers) == 0 && reqCopy.Body == "" && reqCopy.Raw == "" && (reqCopy.Type == "" || strings.EqualFold(reqCopy.Type, common.HttpType)) {
				key := common.RemoveTrailingSlash(urlStr) + "\x00" + strconv.FormatBool(ruleOpts.FollowRedirects)
				var value any
				value, err, _ = baseInfo.requests.Do(key, func() (any, error) {
					if hit, req, resp := cache.ShouldUseCache(ruleCopy, urlStr); hit {
						return &CacheRequest{Request: req, Response: resp}, nil
					}
					variables, err := finger.SendRequest(ctx, r.httpClient, target, reqCopy, ruleCopy.Value, varMap, ruleOpts)
					if err != nil {
						return nil, err
					}
					cache.updateOwnedTargetCache(variables, urlStr, ruleOpts.FollowRedirects)
					req, _ := variables["request"].(*proto.Request)
					resp, _ := variables["response"].(*proto.Response)
					return &CacheRequest{Request: req, Response: resp}, nil
				})
				if err == nil {
					shared := value.(*CacheRequest)
					varMap["request"], varMap["response"] = shared.Request, shared.Response
				}
			} else {
				var newVarMap map[string]any
				newVarMap, err = finger.SendRequest(ctx, r.httpClient, target, reqCopy, ruleCopy.Value, varMap, ruleOpts)
				if err == nil && len(newVarMap) > 0 {
					varMap = newVarMap
					if len(reqCopy.Headers) == 0 && reqCopy.Raw == "" && (reqCopy.Type == "" || reqCopy.Type == common.HttpType) {
						cache.updateOwnedTargetCache(varMap, urlStr, ruleOpts.FollowRedirects)
					}
				}
			}
			if err != nil {
				r.log.Debug("规则 %s 请求失败: %v", ruleCopy.Key, err)
				customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
				continue
			}
		}

		customLib.SetEvidenceEnabled(r.cfg.CaptureEvidence)
		result, err := customLib.Evaluate(ruleCopy.Value.Expression, varMap)
		ruleMatched := false
		if err != nil {
			r.log.Debug("规则 %s CEL解析错误：%v", ruleCopy.Key, err)
			customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
		} else {
			if rb, ok := result.Value().(bool); ok {
				ruleMatched = rb
				customLib.WriteRuleFunctionsROptions(ruleCopy.Key, rb)
			} else {
				r.log.Debug("规则 %s CEL结果非布尔值（%T）", ruleCopy.Key, result.Value())
				customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
			}
		}

		if ruleMatched {
			var detail SubRuleMatch
			captureDetail := r.cfg.CaptureEvidence && len(matchedRules) < 64
			if r.cfg.CaptureEvidence && !captureDetail {
				detailsTruncated = true
			}
			if captureDetail {
				detail = SubRuleMatch{Key: ruleCopy.Key, Expression: ruleCopy.Value.Expression, Method: reqCopy.Method, Path: reqCopy.Path, URL: urlStr}
				if response, ok := varMap["response"].(*proto.Response); ok {
					detail.StatusCode = response.Status
				}
				detail.Evidence, detail.EvidenceTruncated = customLib.Evidence(varMap)
			}
			if len(ruleCopy.Value.Output) > 0 {
				customLib.SetEvidenceEnabled(false)
				outputs := finger.EvaluateOutput(ruleCopy.Value.Output, varMap, customLib)
				if found := strings.TrimSpace(outputs["product_version"]); found != "" {
					if !slices.Contains(versions, found) {
						if len(versions) < 16 {
							versions = append(versions, found)
						} else {
							versionConflict = true
						}
					}
				}
				if captureDetail {
					detail.Outputs = outputs
				}
			}
			if captureDetail {
				matchedRules = append(matchedRules, detail)
			}
		}
	}

	result, err := customLib.Evaluate(fg.Expression, varMap)
	if err != nil {
		return nil, fmt.Errorf("最终表达式解析错误：%w", err)
	}
	rb, ok := result.Value().(bool)
	if !ok {
		r.log.Debug("最终表达式 %q 返回非布尔值（%T），视为不匹配", fg.Expression, result.Value())
	}
	if !rb {
		return nil, nil
	}
	resultData := acquireFingerMatch(fg)
	resultData.Result = true
	resultData.MatchedRules = matchedRules
	resultData.DetailsTruncated = detailsTruncated
	resultData.ProductVersions = versions
	resultData.VersionConflict = versionConflict || len(versions) > 1
	if !resultData.VersionConflict && len(versions) == 1 {
		resultData.ProductVersion = versions[0]
	}
	if req, ok := varMap["request"].(*proto.Request); ok {
		resultData.Request = req
	}
	if resp, ok := varMap["response"].(*proto.Response); ok {
		resultData.Response = resp
	}
	return resultData, nil
}

func calculateResultBuffer(ruleCount int) int {
	if ruleCount < 1 {
		return 1
	}
	buffer := ruleCount / 8
	if buffer < 64 {
		buffer = 64
	}
	if buffer > 2048 {
		buffer = 2048
	}
	if buffer > ruleCount {
		buffer = ruleCount
	}
	return buffer
}
