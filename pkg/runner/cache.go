/*
Package runner 请求 / 响应缓存。

底层基于 otter.Cache（W-TinyLFU 自适应淘汰算法）：
TTL 由 ExpiryWriting 自动维护，条目权重同时限制响应字节和数量。
目标归属保存在条目内，失效时无需维护独立索引。

CacheManager 完全实例化，调用方持有独立缓存。
*/
package runner

import (
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/maypok86/otter/v2"
	otterstats "github.com/maypok86/otter/v2/stats"
	gproto "google.golang.org/protobuf/proto"
)

// CacheRequest 缓存条目，保存原始 proto.Request / proto.Response。
type CacheRequest struct {
	Request   *proto.Request  `json:"request"`
	Response  *proto.Response `json:"response"`
	targetKey string
	Timestamp int64 `json:"timestamp"`
}

type requestCacheKey struct {
	scope     uint64
	key       string
	method    string
	redirects bool
}

// CacheManager 请求 / 响应缓存管理器。
type CacheManager struct {
	log       logger.Sink
	cache     *otter.Cache[requestCacheKey, *CacheRequest]
	scope     uint64
	nextScope *atomic.Uint64
	maxSize   int
	ttl       time.Duration
	createdAt time.Time
	maxBytes  uint64
}

// NewCacheManager 创建缓存管理器实例。
// maxSize <= 0 时回退到 2048；ttl <= 0 时回退到 10 分钟。
func NewCacheManager(maxSize int, ttl time.Duration) *CacheManager {
	return NewCacheManagerWithBudget(maxSize, ttl, 64<<20)
}

func NewCacheManagerWithBudget(maxSize int, ttl time.Duration, maxBytes uint64) *CacheManager {
	if maxBytes == 0 {
		maxBytes = 64 << 20
	}
	if maxSize <= 0 {
		maxSize = 2048
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	cm := &CacheManager{log: logger.Current(),
		maxSize:   maxSize,
		maxBytes:  maxBytes,
		ttl:       ttl,
		createdAt: time.Now(),
		nextScope: &atomic.Uint64{},
	}
	opts := &otter.Options[requestCacheKey, *CacheRequest]{
		MaximumWeight: maxBytes,
		Weigher: func(_ requestCacheKey, e *CacheRequest) uint32 {
			n := uint64(gproto.Size(e.Request) + gproto.Size(e.Response) + 256)
			minWeight := (maxBytes + uint64(maxSize) - 1) / uint64(maxSize)
			if n < minWeight {
				n = minWeight
			}
			if n > 1<<32-1 {
				n = 1<<32 - 1
			}
			return uint32(n)
		},
		InitialCapacity:  maxSize / 2,
		ExpiryCalculator: otter.ExpiryWriting[requestCacheKey, *CacheRequest](ttl),
		StatsRecorder:    otterstats.NewCounter(),
	}
	c, err := otter.New(opts)
	if err != nil {
		logger.Error("初始化 otter 缓存失败，降级到无 TTL 实现: %v", err)
		c = otter.Must(&otter.Options[requestCacheKey, *CacheRequest]{MaximumSize: maxSize})
	}
	cm.cache = c
	return cm
}

// newScope 隔离同一目标的并发扫描，共用实例缓存容量和后台维护。
// 作用域只复制不可变配置，不创建独立缓存或维护协程。
func (cm *CacheManager) newScope() *CacheManager {
	scoped := *cm
	scoped.scope = cm.nextScope.Add(1)
	return &scoped
}

func (cm *CacheManager) clearScope() {
	for key := range cm.cache.All() {
		if key.scope == cm.scope {
			cm.cache.Invalidate(key)
		}
	}
}

// Get 读取缓存条目；命中时返回 (entry, true)。
func (cm *CacheManager) Get(key string) (*CacheRequest, bool) {
	if cm == nil || cm.cache == nil {
		return nil, false
	}
	return cm.cache.GetIfPresent(requestCacheKey{scope: cm.scope, key: key})
}

// Set 写入只读条目，超过单条字节预算时跳过缓存。
func (cm *CacheManager) Set(targetKey, cacheKey string, entry *CacheRequest) {
	if cm == nil {
		return
	}
	cm.set(targetKey, requestCacheKey{scope: cm.scope, key: cacheKey}, entry)
}

func (cm *CacheManager) set(targetKey string, cacheKey requestCacheKey, entry *CacheRequest) {
	if cm == nil || cm.cache == nil || entry == nil {
		return
	}
	if uint64(gproto.Size(entry.Request)+gproto.Size(entry.Response)+256) > cm.maxBytes {
		return
	}
	owned := *entry
	owned.targetKey = targetKey
	cm.cache.Set(cacheKey, &owned)
}

func (cm *CacheManager) requestKey(target, method string, redirects bool) requestCacheKey {
	return requestCacheKey{scope: cm.scope, key: target, method: method, redirects: redirects}
}

// Invalidate 删除单条缓存。
func (cm *CacheManager) Invalidate(cacheKey string) {
	if cm == nil || cm.cache == nil {
		return
	}
	cm.cache.Invalidate(requestCacheKey{scope: cm.scope, key: cacheKey})
}

// InvalidateTarget 删除指定 host 下所有缓存条目，返回删除数量。
func (cm *CacheManager) InvalidateTarget(targetKey string) int {
	if cm == nil || cm.cache == nil || targetKey == "" {
		return 0
	}
	count := 0
	for key, entry := range cm.cache.All() {
		if key.scope == cm.scope && entry.targetKey == targetKey {
			cm.cache.Invalidate(key)
			count++
		}
	}
	return count
}

// InvalidateAll 清空所有缓存。
func (cm *CacheManager) InvalidateAll() {
	if cm == nil || cm.cache == nil {
		return
	}
	cm.cache.InvalidateAll()
}

// Stats 返回缓存统计快照。
func (cm *CacheManager) Stats() map[string]interface{} {
	if cm == nil || cm.cache == nil {
		return map[string]interface{}{}
	}
	stats := cm.cache.Stats()
	hosts := make(map[string]struct{})
	for _, entry := range cm.cache.All() {
		hosts[entry.targetKey] = struct{}{}
	}
	hostCount := len(hosts)
	return map[string]interface{}{
		"total_entries": cm.cache.EstimatedSize(),
		"max_size":      cm.maxSize,
		"max_bytes":     cm.maxBytes,
		"ttl_minutes":   cm.ttl.Minutes(),
		"created_at":    cm.createdAt.Format(time.RFC3339),
		"tracked_urls":  hostCount,
		"hits":          stats.Hits,
		"misses":        stats.Misses,
		"evictions":     stats.Evictions,
		"hit_ratio":     stats.HitRatio(),
	}
}

// Close 释放底层 otter 后台 goroutine。
func (cm *CacheManager) Close() {
	if cm == nil || cm.cache == nil {
		return
	}
	cm.cache.StopAllGoroutines()
}

// ShouldUseCache 判断当前规则是否可命中缓存。命中条件：
//  1. 协议为 HTTP/HTTPS（type 为空或 "http"）
//  2. 方法为 GET / POST
//  3. headers 与 body 均为空
//  4. 缓存中存在对应键且未过期
func (cm *CacheManager) ShouldUseCache(rule finger.RuleMap, target string) (bool, *proto.Request, *proto.Response) {
	reqType := strings.ToLower(rule.Value.Request.Type)
	method := strings.ToUpper(rule.Value.Request.Method)
	if reqType != "" && reqType != common.HttpType {
		return false, nil, nil
	}
	if rule.Value.Request.Raw != "" || len(rule.Value.Request.Headers) > 0 || rule.Value.Request.Body != "" {
		return false, nil, nil
	}
	if method != "GET" && method != "POST" {
		return false, nil, nil
	}
	if target == "" {
		return false, nil, nil
	}

	urlStr := common.RemoveTrailingSlash(target)
	// actualFollowRedirects 与 pkg/finger/runner.go 中实际请求行为对齐（!rule.Request.FollowRedirects）；
	// 缓存键必须反映真实重定向行为，否则查 cache 时永远 miss。
	actualFollowRedirects := !rule.Value.Request.FollowRedirects
	cacheKey := cm.requestKey(urlStr, method, actualFollowRedirects)
	if logger.IsDebugEnabled(cm.log) {
		cm.log.Debug("读取请求缓存：%s %s %t", urlStr, method, actualFollowRedirects)
	}

	entry, ok := cm.cache.GetIfPresent(cacheKey)
	if !ok || entry == nil || entry.Request == nil || entry.Response == nil {
		return false, nil, nil
	}
	return true, entry.Request, entry.Response
}

// UpdateTargetCache 更新缓存：仅在 headers / body 为空且方法为 GET / POST 时生效。
func (cm *CacheManager) UpdateTargetCache(variableMap map[string]any, target string, followRedirects bool) {
	cm.updateTargetCache(variableMap, target, followRedirects, false)
}

// updateOwnedTargetCache 接收本次扫描独占构造的消息。规则只读取消息并替换
// 变量表中的引用，因此扫描作用域可以共享正文，无需再做 protobuf 深拷贝。
// 公共写入接口复制调用方消息；字节预算只决定是否缓存，不裁剪响应。
func (cm *CacheManager) updateOwnedTargetCache(variableMap map[string]any, target string, followRedirects bool) {
	cm.updateTargetCache(variableMap, target, followRedirects, true)
}

func (cm *CacheManager) updateTargetCache(variableMap map[string]any, target string, followRedirects, owned bool) {
	if cm == nil || cm.cache == nil {
		return
	}
	var req *proto.Request
	var resp *proto.Response
	if r, ok := variableMap["request"].(*proto.Request); ok {
		req = r
	}
	if r, ok := variableMap["response"].(*proto.Response); ok {
		resp = r
	}
	if req == nil || resp == nil || target == "" {
		return
	}
	// 先检查完整消息的容量，避免为不会缓存的大响应创建深拷贝。
	if uint64(gproto.Size(req)+gproto.Size(resp)+256) > cm.maxBytes {
		return
	}

	method := strings.ToUpper(req.Method)
	if len(req.Body) > 0 {
		return
	}
	if method != "GET" && method != "POST" {
		return
	}

	urlStr := common.RemoveTrailingSlash(target)
	cacheKey := cm.requestKey(urlStr, method, followRedirects)
	targetKey := normalizeTargetKey(urlStr)
	if logger.IsDebugEnabled(cm.log) {
		cm.log.Debug("写入请求缓存：%s %s %t", urlStr, method, followRedirects)
	}

	if !owned {
		req = gproto.Clone(req).(*proto.Request)
		resp = gproto.Clone(resp).(*proto.Response)
	}
	cm.set(targetKey, cacheKey, &CacheRequest{
		Request:   req,
		Response:  resp,
		Timestamp: time.Now().Unix(),
	})
}

// ClearTarget 删除某个 host 下所有缓存。
func (cm *CacheManager) ClearTarget(target string) {
	if target == "" {
		return
	}
	targetKey := normalizeTargetKey(target)
	if targetKey == "" {
		return
	}
	if n := cm.InvalidateTarget(targetKey); n > 0 {
		cm.log.Debug("成功删除URL相关缓存%d项：%s", n, targetKey)
	}
}

func normalizeTargetKey(raw string) string {
	if raw == "" {
		return ""
	}
	candidate := strings.TrimSpace(raw)
	if !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
		candidate = "http://" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host == "" {
		return common.RemoveTrailingSlash(raw)
	}
	parsed.Path = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	return common.RemoveTrailingSlash(parsed.String())
}
