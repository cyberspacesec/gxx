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
	"github.com/cyberspacesec/gxx/internal/lifecycle"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
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

	closed atomic.Bool
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

	// Sink 在构造期传入：otter 初始化失败的降级日志发生在构造函数内部，
	// 事后赋值 r.cache.log 来不及接管它。
	r.cache = newCacheManager(cfg.CacheMaxSize, cfg.CacheTTL, cfg.CacheMaxBytes, r.log)

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

	r.httpClient.SetGlobalRateLimiter(network.NewGlobalRateLimiter(cfg.GlobalRateLimit, cfg.GlobalRateLimitBurst))
	if cfg.RateLimitQPS > 0 && cfg.RateLimitBurst > 0 {
		r.limiter = network.NewHostRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst)
		r.limiter.SetPerPort(cfg.RateLimitPerPort)
		r.httpClient.SetRateLimiter(r.limiter)
	}

	if cfg.EnableMonitor {
		r.monitor.Start()
	}

	return r, nil
}

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
