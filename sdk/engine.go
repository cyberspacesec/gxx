/*
Package sdk Engine 实现。

Engine 持有一个 *runner.Runner 实例，封装所有扫描业务状态：

  - FingerStore：当前 Engine 加载的指纹规则集
  - RulePool：    规则评估协程池
  - CacheManager：请求 / 响应缓存
  - PerformanceMonitor：内存与调度监控器
  - HostRateLimiter：可选的 per-host 令牌桶限流器

多个 Engine 可在同一进程并发存在，每个实例持有独立资源。
*/
package sdk

import (
	"context"
	"errors"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/internal/lifecycle"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/runner"
	"github.com/cyberspacesec/gxx/v2/pkg/wappalyzer"
	"github.com/cyberspacesec/gxx/v2/types"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"iter"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scanner 是 Engine 实现的最小可用扫描接口（便于 mock 测试）。
type Scanner interface {
	Scan(ctx context.Context, target string) (*TargetResult, error)
	GetBaseInfo(ctx context.Context, target string) (*BaseInfo, error)
	WappalyzerScan(ctx context.Context, target string) (*TechStack, error)
	Close() error
}

// 编译期断言：*Engine 必须实现 Scanner 接口。
var _ Scanner = (*Engine)(nil)

// TargetCallback 流式回调签名。
// 每完成一个目标立即触发 cb；返回 false 时取消尚未开始或进行中的后续扫描。
type TargetCallback func(result *TargetResult) bool

// Engine 指纹识别引擎实例。
type Engine struct {
	life        *lifecycle.Gate
	cfg         engineConfig
	runner      *runner.Runner
	writer      Writer
	closed      atomic.Bool
	products    map[string]ProductInfo
	assessments map[string]RuleAssessment
}

// NewEngine 创建并初始化 Engine 实例。
//
// 调用方负责在不再使用时执行 engine.Close() 释放资源。
//
//	engine, err := sdk.NewEngine(ctx,
//	    sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "fingerYaml"}),
//	    sdk.WithTimeout(15 * time.Second),
//	    sdk.WithRuleConcurrency(500),
//	    sdk.WithRateLimit(50, 100),
//	)
//	if err != nil { return err }
//	defer engine.Close()
func NewEngine(ctx context.Context, opts ...Option) (*Engine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := defaultEngineConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	if cfg.debug && cfg.logger == nil {
		cfg.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	scanCfg := runner.ScanConfig{
		CaptureEvidence:    cfg.matchDetails,
		Reverse:            cfg.reverse,
		Logger:             logger.FromSlog(cfg.logger),
		CacheMaxBytes:      uint64(cfg.cacheMaxBytes),
		Proxy:              cfg.proxy,
		Timeout:            cfg.timeout,
		URLWorkerCount:     cfg.urlConcurrency,
		FingerWorkerCount:  cfg.ruleConcurrency,
		CacheMaxSize:       cfg.cacheMaxSize,
		CacheTTL:           cfg.cacheTTL,
		MemHighBytes:       cfg.memHighBytes,
		MemCriticalBytes:   cfg.memCriticalBytes,
		EnableMonitor:      cfg.enableMonitor,
		EnableProactive:    cfg.enableProactive,
		RateLimitQPS:       cfg.rateLimitQPS,
		RateLimitBurst:     cfg.rateLimitBurst,
		DisableKeepAlives:  cfg.disableKeepAlives,
		InsecureSkipVerify: cfg.insecureSkipVerify,
		CustomHeaders:      cfg.customHeaders,
		Debug:              cfg.debug,
	}
	if !cfg.enableRateLimit {
		scanCfg.RateLimitQPS = 0
		scanCfg.RateLimitBurst = 0
	}

	r, err := runner.NewRunner(scanCfg, cfg.fingerOptions.toInternal())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEngineNotReady, err)
	}
	if r.FingerCount() == 0 {
		_ = r.Close()
		return nil, fmt.Errorf("%w: no rules loaded", ErrFingerNotLoaded)
	}

	if cfg.disableKeepAlives && r.HTTPClient() != nil {
		r.HTTPClient().SetDisableKeepAlives(true)
	}

	writer, err := buildWriter(cfg)
	if err != nil {
		_ = r.Close()
		return nil, err
	}

	products, err := productIndex(cfg.products)
	if err != nil {
		_ = r.Close()
		_ = writer.Close()
		return nil, err
	}
	assessments := make(map[string]RuleAssessment, len(builtinCatalog.Validations)+len(cfg.assessments))
	for id, assessment := range builtinCatalog.Validations {
		assessments[id] = assessment
	}
	for _, assessment := range cfg.assessments {
		assessments[assessment.RuleID] = assessment
	}
	return &Engine{cfg: cfg, runner: r, writer: writer, life: lifecycle.New(0), products: products, assessments: assessments}, nil
}

// buildWriter 根据 engineConfig 装配最终的 Writer：
//   - 同时启用 file / sock / custom 时合并为 MultiWriter；
//   - 没有任何输出配置时返回 NopWriter，保证 Engine.writer 永远非空。
func buildWriter(cfg engineConfig) (Writer, error) {
	var writers []Writer

	if strings.TrimSpace(cfg.outputFile) != "" {
		fw, err := NewFileWriter(cfg.outputFile, cfg.outputFormat)
		if err != nil {
			return nil, fmt.Errorf("init file writer: %w", err)
		}
		writers = append(writers, fw)
	}
	if strings.TrimSpace(cfg.sockOutputFile) != "" {
		sw, err := NewSockWriter(cfg.sockOutputFile)
		if err != nil {
			closeWriters(writers)
			return nil, fmt.Errorf("init sock writer: %w", err)
		}
		writers = append(writers, sw)
	}
	writers = append(writers, cfg.customWriters...)

	switch len(writers) {
	case 0:
		return NopWriter(), nil
	case 1:
		return writers[0], nil
	default:
		return NewMultiWriter(writers...), nil
	}
}

// closeWriters 在构造失败时回滚已创建的 Writer，避免文件句柄 / 监听器泄漏。
func closeWriters(writers []Writer) {
	for _, w := range writers {
		if w != nil {
			_ = w.Close()
		}
	}
}

// Close 释放 Engine 持有的所有资源（线程安全，可重复调用）。
//
// 关闭顺序：取消并等待在途扫描，释放 Runner，再刷新并关闭 Writer。
func (e *Engine) Close() error {
	e.closed.Store(true)
	return e.life.Close(func() error {
		var errs []error
		if e.runner != nil {
			errs = append(errs, e.runner.Close())
		}
		if e.writer != nil {
			errs = append(errs, e.writer.Close())
		}
		return errors.Join(errs...)
	})
}

// IsClosed 引擎是否已 Close。
func (e *Engine) IsClosed() bool { return e.closed.Load() }

// FingerCount 当前加载的指纹规则数量。
func (e *Engine) FingerCount() int {
	if e.runner == nil {
		return 0
	}
	return e.runner.FingerCount()
}

// PoolStats 规则池统计快照。
func (e *Engine) PoolStats() PoolStats {
	if e.runner == nil {
		return PoolStats{}
	}
	s := e.runner.PoolStats()
	return PoolStats{TotalTasks: s.TotalTasks, CompletedTasks: s.CompletedTasks, FailedTasks: s.FailedTasks}
}

// ResetPoolStats 重置规则池统计计数。
func (e *Engine) ResetPoolStats() {
	if e.runner != nil {
		e.runner.ResetPoolStats()
	}
}

// CacheStats 缓存统计快照。
func (e *Engine) CacheStats() map[string]interface{} {
	if e.runner == nil {
		return map[string]interface{}{}
	}
	return e.runner.CacheStats()
}

// MemoryStats 实时内存快照。
func (e *Engine) MemoryStats() MemoryStats {
	if e.runner == nil {
		return MemoryStats{}
	}
	return e.runner.MemoryStats()
}

// SetMemoryThresholds 动态调整内存阈值。
func (e *Engine) SetMemoryThresholds(highBytes, criticalBytes uint64) {
	if e.runner != nil {
		e.runner.SetMemoryThresholds(highBytes, criticalBytes)
	}
}

// EnableMemoryMonitor 运行期开关内存监控。
func (e *Engine) EnableMemoryMonitor(on bool) {
	if e.runner != nil {
		e.runner.EnableMemoryMonitor(on)
	}
}

// HostRateLimiter 返回当前 Engine 持有的限流器（可能为 nil）。
func (e *Engine) HostRateLimiter() *HostRateLimiter {
	if e.runner == nil {
		return nil
	}
	return e.runner.HostRateLimiter()
}

// LoadFingerOptions 运行期重新加载指纹规则。
func (e *Engine) LoadFingerOptions(opts FingerOptions) error {
	if e.IsClosed() {
		return ErrEngineClosed
	}
	if e.runner == nil {
		return ErrEngineNotReady
	}
	if err := e.runner.LoadFingerOptions(opts.toInternal()); err != nil {
		return fmt.Errorf("%w: %w", ErrLoadFinger, err)
	}
	return nil
}

// Scan 对单个目标执行完整指纹识别。
//
// 扫描结果在返回调用方之前会先送入 Writer；Writer 失败仅记录日志，
// 不影响 Scan 的返回值，调用方仍能拿到完整的 *TargetResult。
func (e *Engine) Scan(ctx context.Context, target string) (*TargetResult, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, ErrEmptyTarget
	}
	res, err := e.runner.ScanTarget(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scan target %q: %w", target, errors.Join(ErrScanFailed, err))
	}
	if res == nil {
		return nil, fmt.Errorf("%w: target=%s", ErrEmptyResult, target)
	}
	out := e.convertTargetResult(res)
	e.dispatchWriter(ctx, out)
	return out, nil
}

// dispatchWriter 把扫描结果交给已配置的 Writer，失败由实例日志记录。
// 拆出独立方法以便 Scan / ScanCallback / ScanBatch 复用。
func (e *Engine) dispatchWriter(ctx context.Context, r *TargetResult) {
	if e == nil || e.writer == nil || r == nil {
		return
	}
	if err := e.writer.Write(ctx, r); err != nil {
		logger.FromSlog(e.cfg.logger).Error("写入扫描结果失败: %v", err)
	}
}

// ScanBatch 批量扫描目标，等待所有目标完成后一次性返回结果列表。
func (e *Engine) ScanBatch(ctx context.Context, targets []string) ([]*TargetResult, error) {
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	results := make([]*TargetResult, 0, len(targets))
	var mu sync.Mutex
	cb := func(r *TargetResult) bool {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
		return true
	}
	if err := e.ScanCallback(ctx, targets, cb); err != nil {
		return results, err
	}
	return results, nil
}

// ScanCallback 对一批目标执行流式扫描。
// 每完成一个目标立即调用 cb；cb 返回 false 时通过派生 context 取消后续派发与进行中的 ScanTarget。
func (e *Engine) ScanCallback(ctx context.Context, targets []string, cb TargetCallback) error {
	return e.ScanIterator(ctx, func(yield func(string) bool) {
		for _, target := range targets {
			if !yield(target) {
				return
			}
		}
	}, cb)
}

// ScanIterator 按并发预算从迭代器拉取目标，完成后串行调用 cb。
// 迭代器须遵守 yield 返回 false 即停止的约定，并自行处理输入源的取消。
// 不保留成功结果；目标错误按 ScanCallback 的约定聚合返回。
func (e *Engine) ScanIterator(ctx context.Context, targets iter.Seq[string], cb TargetCallback) error {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return err
	}
	defer done()
	if e.IsClosed() {
		return ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cb == nil {
		return fmt.Errorf("%w: callback must not be nil", ErrInvalidOption)
	}
	if targets == nil {
		return fmt.Errorf("%w: target iterator must not be nil", ErrInvalidOption)
	}

	concurrency := e.cfg.urlConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	batchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var cbMu sync.Mutex
	var cbStopped atomic.Bool
	var errorMu sync.Mutex
	var targetErrors []error

	for t := range targets {
		if batchCtx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-batchCtx.Done():
		}
		if batchCtx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			if batchCtx.Err() != nil {
				return
			}
			res, err := e.runner.ScanTarget(batchCtx, target)
			if batchCtx.Err() != nil {
				return
			}
			if err != nil || res == nil {
				if err == nil {
					err = ErrEmptyResult
				}
				errorMu.Lock()
				targetErrors = append(targetErrors, fmt.Errorf("target %q: %w", target, err))
				errorMu.Unlock()
				return
			}

			out := e.convertTargetResult(res)
			e.dispatchWriter(batchCtx, out)

			cbMu.Lock()
			defer cbMu.Unlock()
			if cbStopped.Load() || batchCtx.Err() != nil {
				return
			}
			if !cb(out) {
				cbStopped.Store(true)
				cancel()
			}
		}(t)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.Join(targetErrors...)
}

// GetBaseInfo 仅获取目标基础信息（不执行指纹匹配）。
func (e *Engine) GetBaseInfo(ctx context.Context, target string) (*BaseInfo, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, ErrEmptyTarget
	}
	base, err := e.runner.GetBaseInfo(ctx, target)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, fmt.Errorf("%w: target=%s", ErrEmptyResult, target)
	}
	info := &BaseInfo{
		Target:     base.Url,
		Title:      base.Title,
		StatusCode: base.StatusCode,
		ICP:        base.ICP,
	}
	if base.Server != nil {
		info.Server = convertServerInfo(base.Server)
	}
	if base.Wappalyzer != nil {
		info.TechStack = convertTechStack(base.Wappalyzer)
	}
	if len(base.Certs) > 0 {
		info.Certs = convertCerts(base.Certs)
	}
	return info, nil
}

// WappalyzerScan 仅做技术栈识别。
func (e *Engine) WappalyzerScan(ctx context.Context, target string) (*TechStack, error) {
	info, err := e.GetBaseInfo(ctx, target)
	if err != nil {
		return nil, err
	}
	if info.TechStack == nil {
		return nil, fmt.Errorf("%w: tech stack unavailable for %s", ErrEmptyResult, target)
	}
	return info.TechStack, nil
}

// NormalizeURL 规范化目标地址（http / https 自动探测）。
func (e *Engine) NormalizeURL(ctx context.Context, target string) (string, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return "", err
	}
	defer done()
	ctx = logger.WithContext(ctx, logger.FromSlog(e.cfg.logger))
	if e.IsClosed() {
		return "", ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if e.runner.HTTPClient() == nil {
		return "", fmt.Errorf("%w: http client not initialized", ErrEngineNotReady)
	}
	timeout := e.cfg.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return e.runner.HTTPClient().CheckProtocol(ctx, target, e.cfg.proxy, timeout)
}

// ─────────────── 内部转换 ───────────────

func (e *Engine) convertTargetResult(r *runner.TargetResult) *TargetResult {
	tr := &TargetResult{
		URL:        r.URL,
		StatusCode: r.StatusCode,
		Title:      r.Title,
		ICP:        r.ICP,
		Matches:    make([]FingerMatch, 0),
	}
	if r.Server != nil {
		tr.Server = convertServerInfo(r.Server)
	}
	if r.Wappalyzer != nil {
		tr.TechStack = convertTechStack(r.Wappalyzer)
	}
	if len(r.Certs) > 0 {
		tr.Certs = convertCerts(r.Certs)
	}
	for _, m := range r.Matches {
		if m == nil || m.Finger == nil {
			continue
		}
		tr.Matches = append(tr.Matches, FingerMatch{
			Info:             e.convertFingerInfo(finger.Metadata{ID: m.Finger.Id, Info: m.Finger.Info, Source: m.Finger.Source}),
			Result:           m.Result,
			Expression:       m.Finger.Expression,
			ProductVersion:   m.ProductVersion,
			ProductVersions:  m.ProductVersions,
			VersionConflict:  m.VersionConflict,
			DetailsTruncated: m.DetailsTruncated,
			MatchedRules:     convertSubRuleMatches(m.MatchedRules),
		})
	}
	tr.Products = aggregateProducts(tr.Matches)
	return tr
}

func convertServerInfo(s *types.ServerInfo) *ServerInfo {
	return &ServerInfo{
		OriginalServer: s.OriginalServer,
		ServerType:     s.ServerType,
		Version:        s.Version,
	}
}

func convertTechStack(w *wappalyzer.TypeWappalyzer) *TechStack {
	return &TechStack{
		WebServers:           w.WebServers,
		ReverseProxies:       w.ReverseProxies,
		JavaScriptFrameworks: w.JavaScriptFrameworks,
		JavaScriptLibraries:  w.JavaScriptLibraries,
		WebFrameworks:        w.WebFrameworks,
		StaticSiteGenerator:  w.StaticSiteGenerator,
		ProgrammingLanguages: w.ProgrammingLanguages,
		Caching:              w.Caching,
		Security:             w.Security,
		HostingPanels:        w.HostingPanels,
		Other:                w.Other,
	}
}

func convertCerts(certs []*types.CertInfo) []CertInfo {
	result := make([]CertInfo, 0, len(certs))
	for _, c := range certs {
		if c == nil {
			continue
		}
		result = append(result, CertInfo{
			Subject:               convertCertName(c.Subject),
			Issuer:                convertCertName(c.Issuer),
			NotBefore:             c.NotBefore,
			NotAfter:              c.NotAfter,
			Valid:                 c.Valid,
			SerialNumber:          c.SerialNumber,
			PublicKeyAlgorithm:    c.PublicKeyAlgorithm,
			PublicKey:             c.PublicKey,
			SignatureAlgorithm:    c.SignatureAlgorithm,
			Version:               c.Version,
			DNSNames:              c.DNSNames,
			IPAddresses:           c.IPAddresses,
			EmailAddresses:        c.EmailAddresses,
			OCSPServer:            c.OCSPServer,
			CRLDistributionPoints: c.CRLDistributionPoints,
		})
	}
	return result
}

func convertCertName(n types.CertName) CertName {
	return CertName{
		CommonName:         n.CommonName,
		Organization:       n.Organization,
		OrganizationalUnit: n.OrganizationalUnit,
		Country:            n.Country,
		Province:           n.Province,
		Locality:           n.Locality,
		StreetAddress:      n.StreetAddress,
		PostalCode:         n.PostalCode,
		SerialNumber:       n.SerialNumber,
	}
}
