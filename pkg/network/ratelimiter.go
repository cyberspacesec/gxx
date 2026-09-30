/*
Package network per-host rate limiter。

每个目标 host 独立持有一个 *rate.Limiter（令牌桶），
使用 phuslu/lru 作为 LRU 容器（容量 hostLimiterCacheSize），
过期 host 自动 evict；Limiter 在 host 首次访问时才创建。

完全实例化：调用方 NewHostRateLimiter(qps, burst) 创建并持有，
不存在任何包级 limiter。
*/
package network

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/phuslu/lru"
	"golang.org/x/time/rate"
)

// hostLimiterCacheSize per-host limiter 缓存上限。
const hostLimiterCacheSize = 512

// HostRateLimiter per-host 令牌桶限流器集合。
//
// 用法：
//
//	limiter := NewHostRateLimiter(50, 100) // 50 QPS / burst 100
//	if err := limiter.Wait(ctx, "https://example.com"); err != nil { return err }
//
// qps / burst 任一为非正值时 NewHostRateLimiter 返回 nil，
// Wait / Allow 对 nil 接收器是 no-op（始终返回放行）。
type HostRateLimiter struct {
	qps     float64
	burst   int
	cache   *lru.LRUCache[string, *rate.Limiter]
	enabled atomic.Bool
	mu      sync.Mutex
}

// NewHostRateLimiter 创建 per-host 限流器。
// qps <= 0 或 burst <= 0 时返回 nil（视为禁用）。
func NewHostRateLimiter(qps float64, burst int) *HostRateLimiter {
	if qps <= 0 || burst <= 0 {
		return nil
	}
	l := &HostRateLimiter{
		qps:   qps,
		burst: burst,
		cache: lru.NewLRUCache[string, *rate.Limiter](hostLimiterCacheSize),
	}
	l.enabled.Store(true)
	return l
}

// SetEnabled 运行期临时切换启用状态。
func (h *HostRateLimiter) SetEnabled(on bool) {
	if h == nil {
		return
	}
	h.enabled.Store(on)
}

// Wait 阻塞等待 host 的令牌可用，或 ctx 超时 / 取消。
// 当 limiter 为 nil 或被禁用时立即返回 nil（fast path）。
func (h *HostRateLimiter) Wait(ctx context.Context, target string) error {
	if h == nil || !h.enabled.Load() {
		return nil
	}
	host := extractHost(target)
	if host == "" {
		return nil
	}
	return h.getOrCreate(host).Wait(ctx)
}

// Allow 非阻塞判断 host 当前是否有可用令牌。
func (h *HostRateLimiter) Allow(target string) bool {
	if h == nil || !h.enabled.Load() {
		return true
	}
	host := extractHost(target)
	if host == "" {
		return true
	}
	return h.getOrCreate(host).Allow()
}

// Stats 返回当前缓存的 host limiter 数量及配置参数。
func (h *HostRateLimiter) Stats() (cachedHosts int, qps float64, burst int) {
	if h == nil {
		return 0, 0, 0
	}
	return h.cache.Len(), h.qps, h.burst
}

// getOrCreate 取或创建指定 host 的 *rate.Limiter（线程安全，双重检查）。
func (h *HostRateLimiter) getOrCreate(host string) *rate.Limiter {
	if cached, ok := h.cache.Get(host); ok {
		return cached
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if cached, ok := h.cache.Get(host); ok {
		return cached
	}
	limiter := rate.NewLimiter(rate.Limit(h.qps), h.burst)
	h.cache.Set(host, limiter)
	return limiter
}

// extractHost 提取目标的 host:port 部分作为限流 key。
func extractHost(target string) string {
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	if u, err := url.Parse("http://" + target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}
