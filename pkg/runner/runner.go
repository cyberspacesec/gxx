/*
Package runner 顶层 Runner 实例。

*Runner 是 GXX 引擎的核心运行时，持有：

  - *FingerStore：指纹规则集
  - *RulePool：规则评估协程池（ants v2 PoolWithFunc）
  - *CacheManager：请求 / 响应缓存（otter v2 W-TinyLFU）
  - *PerformanceMonitor：运行时指标监控
  - *network.HostRateLimiter：可选的 per-host 限流器
  - *network.HTTPClient：实例化 HTTP 客户端

NewRunner 在构造期完成所有资源初始化；Close 统一释放资源。
*/
package runner

import (
	"context"
	"errors"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/internal/lifecycle"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/types"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"github.com/cyberspacesec/gxx/v2/utils/output"
	"maps"
	"sync/atomic"
	"time"
)

// Runner 指纹识别运行时。
type Runner struct {
	life       *lifecycle.Gate
	cfg        ScanConfig
	store      *FingerStore
	pool       *RulePool
	cache      *CacheManager
	monitor    *PerformanceMonitor
	limiter    *network.HostRateLimiter
	httpClient *network.HTTPClient
	log        logger.Sink

	isRunning atomic.Bool
	closed    atomic.Bool
}

// NewRunner 创建并初始化 Runner 实例。
//
// pocOptions 指定指纹规则文件 / 目录；空值时使用嵌入式指纹库。
// 调用方应在不再使用时执行 Runner.Close() 释放资源。
func NewRunner(cfg ScanConfig, pocOptions types.YamlFingerType) (*Runner, error) {
	cfg.CustomHeaders = maps.Clone(cfg.CustomHeaders)
	if cfg.URLWorkerCount <= 0 {
		cfg.URLWorkerCount = DefaultURLWorkers
	}
	if cfg.FingerWorkerCount <= 0 {
		cfg.FingerWorkerCount = DefaultRuleWorkers
	}
	if cfg.CacheMaxSize <= 0 {
		cfg.CacheMaxSize = 2048
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 10 * time.Minute
	}

	if cfg.Logger == nil {
		cfg.Logger = logger.Current()
	}
	r := &Runner{
		log:        cfg.Logger,
		cfg:        cfg,
		life:       lifecycle.New(cfg.URLWorkerCount),
		httpClient: network.NewHTTPClient(),
	}
	if cfg.DisableKeepAlives {
		r.httpClient.SetDisableKeepAlives(true)
	}
	if !cfg.InsecureSkipVerify {
		r.httpClient.SetInsecureSkipVerify(false)
	}
	if cfg.Debug {
		r.httpClient.SetHTTPDebug(true)
	}
	r.store = NewFingerStore(r.log)
	r.store.captureEvidence = cfg.CaptureEvidence
	if err := r.store.Load(pocOptions); err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("加载指纹规则失败: %w", err)
	}
	r.log.Info("加载指纹数量：%v 个", r.store.Count())

	r.cache = NewCacheManagerWithBudget(cfg.CacheMaxSize, cfg.CacheTTL, cfg.CacheMaxBytes)
	r.cache.log = r.log

	pool, err := NewRulePool(cfg.FingerWorkerCount, r.processRuleTask, r.log)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("初始化规则池失败: %w", err)
	}
	r.pool = pool

	initialWorkers := cfg.FingerWorkerCount
	r.monitor = NewPerformanceMonitor(cfg.MemHighBytes, cfg.MemCriticalBytes, func(stats *MemoryStats) {
		current := pool.CurrentWorkers()
		if current > MinRuleWorkers {
			newCap := current / 2
			if newCap < MinRuleWorkers {
				newCap = MinRuleWorkers
			}
			pool.Tune(newCap)
		}
	})
	// 低压恢复回调：连续多 tick 低压力时按 1.5x 步长逐步恢复 worker 容量，
	// 上限不超过初始配置 initialWorkers，避免与 onPressure 的降并发动作互相抖动。
	r.monitor.SetReliefCallback(func(stats *MemoryStats) {
		current := pool.CurrentWorkers()
		if current >= initialWorkers {
			return
		}
		next := current + current/2
		if next <= current {
			next = current + 1
		}
		if next > initialWorkers {
			next = initialWorkers
		}
		if next > MaxRuleWorkers {
			next = MaxRuleWorkers
		}
		pool.Tune(next)
		r.log.Debug("规则池 worker 容量已从 %d 恢复至 %d (初始 %d)", current, next, initialWorkers)
	}, 4, 0.6)
	r.monitor.log = r.log
	r.monitor.EnableProactiveGC(cfg.EnableProactive)

	if cfg.RateLimitQPS > 0 && cfg.RateLimitBurst > 0 {
		r.limiter = network.NewHostRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst)
		r.httpClient.SetRateLimiter(r.limiter)
	}

	if cfg.EnableMonitor {
		r.monitor.Start()
	}

	return r, nil
}

// IsClosed Runner 是否已释放。
func (r *Runner) IsClosed() bool { return r.closed.Load() }

// FingerCount 当前加载的指纹数量。
func (r *Runner) FingerCount() int {
	if r.store == nil {
		return 0
	}
	return r.store.Count()
}

// RuleMetadata 返回当前规则快照的元数据。
func (r *Runner) RuleMetadata() []finger.Metadata { return r.store.Metadata() }

// PoolStats 规则池任务统计快照。
func (r *Runner) PoolStats() RulePoolStats {
	if r.pool == nil {
		return RulePoolStats{}
	}
	return r.pool.Stats()
}

// ResetPoolStats 把规则池统计计数清零。
func (r *Runner) ResetPoolStats() {
	if r.pool != nil {
		r.pool.ResetStats()
	}
}

// CacheStats 缓存统计快照。
func (r *Runner) CacheStats() map[string]interface{} {
	if r.cache == nil {
		return map[string]interface{}{}
	}
	return r.cache.Stats()
}

// MemoryStats 实时内存快照。
func (r *Runner) MemoryStats() MemoryStats {
	if r.monitor == nil {
		return readRuntimeMetrics()
	}
	return r.monitor.Snapshot()
}

// SetMemoryThresholds 动态调整内存阈值。
func (r *Runner) SetMemoryThresholds(high, critical uint64) {
	if r.monitor != nil {
		r.monitor.SetThresholds(high, critical)
	}
}

// EnableMemoryMonitor 运行期开关监控器。
func (r *Runner) EnableMemoryMonitor(on bool) {
	ctx, done, err := r.life.Begin(context.Background())
	_ = ctx
	if err != nil {
		return
	}
	defer done()
	if r.monitor == nil {
		return
	}
	if on {
		r.monitor.Start()
	} else {
		r.monitor.Stop()
	}
}

// LoadFingerOptions 重新加载指纹规则。
func (r *Runner) LoadFingerOptions(opts types.YamlFingerType) error {
	_, done, err := r.life.Begin(context.Background())
	if err != nil {
		return err
	}
	defer done()
	if r.store == nil {
		return fmt.Errorf("finger store not initialized")
	}
	return r.store.Load(opts)
}

// HostRateLimiter 返回当前 Runner 持有的限流器（可能为 nil）。
func (r *Runner) HostRateLimiter() *network.HostRateLimiter { return r.limiter }

// Close 释放 Runner 持有的所有资源（线程安全，可重复调用）。
func (r *Runner) Close() error {
	r.closed.Store(true)
	return r.life.Close(func() error {
		if r.monitor != nil {
			r.monitor.Stop()
		}
		var errs []error
		if r.pool != nil {
			errs = append(errs, r.pool.Release(context.Background()))
		}
		if r.cache != nil {
			r.cache.Close()
		}
		if r.httpClient != nil {
			errs = append(errs, r.httpClient.Close())
		}
		return errors.Join(errs...)
	})
}

// HTTPClient 返回 Runner 持有的 HTTP 客户端。
func (r *Runner) HTTPClient() *network.HTTPClient {
	return r.httpClient
}

// Run 执行批量扫描任务（CLI 入口）。
func (r *Runner) Run(ctx context.Context, options *types.CmdOptions) error {
	if r.IsClosed() {
		return fmt.Errorf("runner has been closed")
	}
	if !r.isRunning.CompareAndSwap(false, true) {
		return fmt.Errorf("扫描器已在运行中")
	}
	defer r.isRunning.Store(false)

	targets := LoadTargets(options)
	if len(targets) == 0 {
		return fmt.Errorf("未找到有效的目标URL")
	}
	r.log.Info("准备扫描 %d 个目标", len(targets))

	if r.cfg.OutputFile != "" {
		if err := output.InitOutput(r.cfg.OutputFile, r.cfg.OutputFormat); err != nil {
			return fmt.Errorf("初始化输出文件失败: %w", err)
		}
		defer func() { _ = output.Close() }()
	}
	if r.cfg.SockOutputFile != "" {
		if err := output.InitSockOutput(r.cfg.SockOutputFile); err != nil {
			return fmt.Errorf("初始化socket输出文件失败: %w", err)
		}
		r.log.Info("Socket输出文件：%s", r.cfg.SockOutputFile)
	}

	r.log.Info("开始扫描 %d 个目标，URL并发=%d 规则并发=%d ...",
		len(targets), r.cfg.URLWorkerCount, r.cfg.FingerWorkerCount)

	summary, err := r.executeScan(ctx, targets, options)
	if err != nil {
		return err
	}

	output.PrintSummaryCounts(len(targets), summary.matched, summary.unmatched)
	return nil
}
