/*
Package debug 提供 GXX 引擎的运维与调试 helper。

本包通过调用方传入的 *sdk.Engine 获取诊断信息。
内存和 GC 数据描述整个 Go 进程，限流器统计描述指定实例。

	import (
	    "github.com/cyberspacesec/gxx/sdk"
	    "github.com/cyberspacesec/gxx/sdk/debug"
	)

	engine, _ := sdk.NewEngine(ctx, sdk.WithMemoryMonitor(true))
	defer engine.Close()

	stats := debug.MemoryStatsOf(engine)            // 实时内存快照
	rl := debug.HostRateLimiterStatsOf(engine)      // 限流器状态
	debug.ForceGC()                                 // 仅诊断时使用
*/
package debug

import (
	"runtime"

	"github.com/cyberspacesec/gxx/sdk"
)

// MemoryStats 内存统计快照（外部友好字段名 + JSON tag）。
type MemoryStats struct {
	HeapAlloc      uint64  `json:"heap_alloc_bytes"`
	HeapSys        uint64  `json:"heap_sys_bytes"`
	HeapIdle       uint64  `json:"heap_idle_bytes"`
	HeapInUse      uint64  `json:"heap_inuse_bytes"`
	NumGC          uint32  `json:"num_gc"`
	GCCPUFraction  float64 `json:"gc_cpu_fraction"`
	MemoryUsage    float64 `json:"memory_usage_percent"`
	NumGoroutine   int     `json:"num_goroutine"`
	GoSchedLatency float64 `json:"go_sched_latency_p99_seconds"`
}

// MemoryStatsOf 通过指定 Engine 读取整个 Go 进程的内存快照。
func MemoryStatsOf(e *sdk.Engine) MemoryStats {
	if e == nil {
		return MemoryStats{}
	}
	s := e.MemoryStats()
	return MemoryStats{
		HeapAlloc:      s.HeapAlloc,
		HeapSys:        s.HeapSys,
		HeapIdle:       s.HeapIdle,
		HeapInUse:      s.HeapInUse,
		NumGC:          s.NumGC,
		GCCPUFraction:  s.GCCPUFraction,
		MemoryUsage:    s.MemoryUsage,
		NumGoroutine:   s.NumGoroutine,
		GoSchedLatency: s.GoSchedLatency,
	}
}

// ForceGC 立即触发一次 GC。
//
// runtime.GC 影响整个进程，并包含短暂的 STW 阶段，可能放大尾延迟。
// 仅在需要主动回收的诊断场景使用。
// 常规生产请改用 sdk.WithProactiveGC(true) 让监控器在压力达阈值时自动调用。
func ForceGC() { runtime.GC() }

// HostRateLimiterStats 当前实例的 per-host limiter 状态快照。
type HostRateLimiterStats struct {
	Enabled     bool    `json:"enabled"`
	CachedHosts int     `json:"cached_hosts"`
	QPS         float64 `json:"qps"`
	Burst       int     `json:"burst"`
}

// HostRateLimiterStatsOf 从指定 Engine 读取 per-host limiter 状态。
// 未启用限流时所有字段返回零值。
func HostRateLimiterStatsOf(e *sdk.Engine) HostRateLimiterStats {
	if e == nil {
		return HostRateLimiterStats{}
	}
	rl := e.HostRateLimiter()
	if rl == nil {
		return HostRateLimiterStats{}
	}
	cached, qps, burst := rl.Stats()
	return HostRateLimiterStats{
		Enabled:     true,
		CachedHosts: cached,
		QPS:         qps,
		Burst:       burst,
	}
}
