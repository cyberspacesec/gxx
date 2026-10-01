/*
Package runner 性能监控器。

基于 runtime/metrics 采集内存、GC、调度延迟等指标，
sample 切片通过 sync.Pool 复用以避免分配。

PerformanceMonitor 完全实例化：调用方持有独立监控器，
可绑定自定义 onPressure 回调以实现降并发等响应策略。
*/
package runner

import (
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryStats 内存统计快照。
type MemoryStats struct {
	HeapAlloc      uint64
	HeapSys        uint64
	HeapIdle       uint64
	HeapInUse      uint64
	NumGC          uint32
	GCCPUFraction  float64
	LastGCTime     time.Time
	MemoryUsage    float64
	NumGoroutine   int
	GoSchedLatency float64
}

// PerformanceMonitor 性能监控器实例。
//
// 监控器周期性采样运行时指标，并通过两类回调驱动调用方做出反应：
//
//   - onPressure：HeapAlloc 超过高阈值或占用率过高时触发，用于降并发等止血动作；
//   - onRelief：  连续 reliefThreshold 个 tick 处于低压状态时触发，
//     调用方可据此逐步恢复 worker 容量，避免压力消除后并发度单调衰减。
type PerformanceMonitor struct {
	log                  logger.Sink
	enabled              atomic.Bool
	stopCh               chan struct{}
	lifeMu               sync.Mutex
	loopDone             chan struct{}
	highMemThreshold     atomic.Uint64
	criticalMemThreshold atomic.Uint64
	goroutineThreshold   int
	proactiveGC          atomic.Bool
	onPressure           func(stats *MemoryStats)
	onRelief             func(stats *MemoryStats)
	callbackMu           sync.RWMutex
	tickInterval         time.Duration

	// reliefStreak 记录连续低压力的 tick 次数；超过 reliefThreshold 触发 onRelief 后清零。
	reliefStreak     int
	reliefThreshold  int
	reliefUsageLimit float64
}

// NewPerformanceMonitor 创建监控器实例。
//
//   - highBytes / criticalBytes: 内存阈值，<= 0 时使用默认 2GB / 4GB
//   - onPressure: 内存压力到达高阈值时的回调；nil 表示仅记录告警
//
// 默认 reliefThreshold = 4（连续 4 tick / ~60s 低压力触发恢复），
// reliefUsageLimit = 0.6（HeapAlloc 占 HeapSys 比例 ≤ 60% 且 < highMem 视为低压力）。
func NewPerformanceMonitor(highBytes, criticalBytes uint64, onPressure func(*MemoryStats)) *PerformanceMonitor {
	if highBytes == 0 {
		highBytes = 2 * 1024 * 1024 * 1024
	}
	if criticalBytes == 0 || criticalBytes < highBytes {
		criticalBytes = 4 * 1024 * 1024 * 1024
	}
	pm := &PerformanceMonitor{log: logger.Current(),
		goroutineThreshold: 15000,
		onPressure:         onPressure,
		tickInterval:       15 * time.Second,
		reliefThreshold:    4,
		reliefUsageLimit:   0.6,
	}
	pm.highMemThreshold.Store(highBytes)
	pm.criticalMemThreshold.Store(criticalBytes)
	return pm
}

// SetReliefCallback 设置低压恢复回调，可在内存压力解除后逐步恢复 worker 容量等。
// 通过 streakThreshold 控制需要连续多少个低压 tick 才触发（默认 4），
// usageLimit 设定低压阈值上限（HeapAlloc / HeapSys，默认 0.6）。
// streakThreshold <= 0 / usageLimit <= 0 时保留默认值。
func (pm *PerformanceMonitor) SetReliefCallback(onRelief func(*MemoryStats), streakThreshold int, usageLimit float64) {
	pm.callbackMu.Lock()
	defer pm.callbackMu.Unlock()
	pm.onRelief = onRelief
	if streakThreshold > 0 {
		pm.reliefThreshold = streakThreshold
	}
	if usageLimit > 0 {
		pm.reliefUsageLimit = usageLimit
	}
}

// SetThresholds 动态调整内存阈值。
func (pm *PerformanceMonitor) SetThresholds(highBytes, criticalBytes uint64) {
	if highBytes > 0 {
		pm.highMemThreshold.Store(highBytes)
	}
	if criticalBytes > 0 {
		pm.criticalMemThreshold.Store(criticalBytes)
	}
}

// EnableProactiveGC 控制压力时是否主动 runtime.GC()。
func (pm *PerformanceMonitor) EnableProactiveGC(on bool) {
	pm.proactiveGC.Store(on)
}

// Start 启动监控（线程安全，重复调用 noop）。
func (pm *PerformanceMonitor) Start() {
	pm.lifeMu.Lock()
	defer pm.lifeMu.Unlock()
	if pm.enabled.Load() {
		return
	}
	pm.stopCh = make(chan struct{})
	pm.loopDone = make(chan struct{})
	pm.enabled.Store(true)
	go pm.loop(pm.stopCh, pm.loopDone)
}
func (pm *PerformanceMonitor) Stop() {
	pm.lifeMu.Lock()
	defer pm.lifeMu.Unlock()
	if !pm.enabled.Swap(false) {
		return
	}
	close(pm.stopCh)
	<-pm.loopDone
}

// Snapshot 实时取一次内存快照（不依赖监控器是否启动）。
func (pm *PerformanceMonitor) Snapshot() MemoryStats { return readRuntimeMetrics() }

func (pm *PerformanceMonitor) loop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(pm.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pm.tick()
		case <-stop:
			return
		}
	}
}

func (pm *PerformanceMonitor) tick() {
	stats := readRuntimeMetrics()
	pm.log.Debug("内存: %.2f MB (%.1f%%), GC: %d, Goroutines: %d, sched-p99: %.3fms",
		float64(stats.HeapAlloc)/1024/1024, stats.MemoryUsage,
		stats.NumGC, stats.NumGoroutine, stats.GoSchedLatency*1000)
	pm.handlePressure(&stats)
	if stats.NumGoroutine > pm.goroutineThreshold {
		pm.log.Debug("Goroutine 数量达到警戒值: %d (> %d)", stats.NumGoroutine, pm.goroutineThreshold)
	}
}

func (pm *PerformanceMonitor) handlePressure(stats *MemoryStats) {
	pm.callbackMu.RLock()
	onRelief, reliefThreshold, reliefUsageLimit := pm.onRelief, pm.reliefThreshold, pm.reliefUsageLimit
	pm.callbackMu.RUnlock()
	high := pm.highMemThreshold.Load()
	critical := pm.criticalMemThreshold.Load()

	// 低压恢复路径：HeapAlloc 远低于高阈值且占用率低，累计连续低压 tick
	// 达到阈值后触发 onRelief。
	usageRatio := 0.0
	if stats.HeapSys > 0 {
		usageRatio = float64(stats.HeapAlloc) / float64(stats.HeapSys)
	}
	if stats.HeapAlloc < high && usageRatio <= reliefUsageLimit {
		pm.reliefStreak++
		if onRelief != nil && pm.reliefStreak >= reliefThreshold {
			pm.log.Debug("内存连续低压 %d tick，触发恢复回调 (HeapAlloc=%dMB, usage=%.1f%%)",
				pm.reliefStreak, stats.HeapAlloc/1024/1024, usageRatio*100)
			onRelief(stats)
			pm.reliefStreak = 0
		}
		return
	}

	if stats.HeapAlloc <= high && stats.MemoryUsage <= 85.0 {
		return
	}

	// 进入压力区，清零低压计数
	pm.reliefStreak = 0
	pm.log.Debug("内存使用超过高阈值或占用率高，触发降压回调")
	if pm.onPressure != nil {
		pm.onPressure(stats)
	}
	if !pm.proactiveGC.Load() {
		pm.log.Debug("proactiveGC=false，仅告警 + 降压")
		return
	}
	runtime.GC()
	if stats.HeapAlloc > critical {
		pm.log.Debug("内存使用达到临界值，调用 FreeOSMemory")
		debug.FreeOSMemory()
	}
}

// readRuntimeMetrics 采集整个 Go 进程的内存与调度统计。
func readRuntimeMetrics() MemoryStats {
	samples := metricSamplesPool.Get().([]metrics.Sample)
	metrics.Read(samples)

	stats := MemoryStats{}
	for _, s := range samples {
		if s.Value.Kind() == metrics.KindBad {
			continue
		}
		switch s.Name {
		case "/memory/classes/heap/objects:bytes":
			stats.HeapAlloc = s.Value.Uint64()
		case "/memory/classes/heap/free:bytes":
			stats.HeapIdle = s.Value.Uint64()
		case "/memory/classes/total:bytes":
			stats.HeapSys = s.Value.Uint64()
		case "/gc/cycles/total:gc-cycles":
			stats.NumGC = uint32(s.Value.Uint64())
		case "/sched/goroutines:goroutines":
			stats.NumGoroutine = int(s.Value.Uint64())
		case "/sched/latencies:seconds":
			stats.GoSchedLatency = histogramP99(s.Value.Float64Histogram())
		}
	}

	// 用 ReadMemStats 补 runtime/metrics 没覆盖的字段（HeapInUse / GCCPUFraction / LastGC）
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if stats.HeapAlloc == 0 {
		stats.HeapAlloc = ms.HeapAlloc
	}
	stats.HeapSys = ms.HeapSys
	stats.HeapIdle = ms.HeapIdle
	stats.HeapInUse = ms.HeapInuse
	stats.GCCPUFraction = ms.GCCPUFraction
	stats.LastGCTime = time.Unix(0, int64(ms.LastGC))

	if stats.HeapSys > 0 {
		stats.MemoryUsage = float64(stats.HeapAlloc) / float64(stats.HeapSys) * 100
	}
	if stats.NumGoroutine == 0 {
		stats.NumGoroutine = runtime.NumGoroutine()
	}

	metricSamplesPool.Put(samples)
	return stats
}

func histogramP99(h *metrics.Float64Histogram) float64 {
	if h == nil || len(h.Counts) == 0 {
		return 0
	}
	var total uint64
	for _, c := range h.Counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	threshold := uint64(float64(total) * 0.99)
	var cum uint64
	for i, c := range h.Counts {
		cum += c
		if cum >= threshold && i < len(h.Buckets) {
			return h.Buckets[i]
		}
	}
	return h.Buckets[len(h.Buckets)-1]
}

// metricSamplesPool 复用 metrics.Sample 切片，避免每 tick 分配。
var metricSamplesPool = sync.Pool{
	New: func() interface{} {
		return []metrics.Sample{
			{Name: "/memory/classes/heap/objects:bytes"},
			{Name: "/memory/classes/heap/free:bytes"},
			{Name: "/memory/classes/total:bytes"},
			{Name: "/gc/cycles/total:gc-cycles"},
			{Name: "/sched/goroutines:goroutines"},
			{Name: "/sched/latencies:seconds"},
		}
	},
}
