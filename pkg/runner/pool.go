/*
Package runner 工作池抽象 + RulePool 实例。

底层基于 ants v2 的 PoolWithFunc，URL 池和规则池分别控制并发容量。
单池保持配置容量的精确语义，避免分桶取整导致实际容量超限。
*/
package runner

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/pkg/cel"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"
)

// Pool 工作池统一接口。
type Pool interface {
	Invoke(args interface{}) error
	Tune(size int)
	Release(ctx context.Context) error
}

type singlePool struct{ inner *ants.PoolWithFunc }

func (p *singlePool) Invoke(args interface{}) error { return p.inner.Invoke(args) }
func (p *singlePool) Tune(size int) {
	if size > 0 {
		p.inner.Tune(size)
	}
}
func (p *singlePool) Release(ctx context.Context) error {
	if ctx == nil {
		return p.inner.ReleaseTimeout(5 * time.Second)
	}
	return p.inner.ReleaseContext(ctx)
}

// NewWorkPoolWithFunc 创建单池 ants.PoolWithFunc 包装，适合 worker 数较少的场景。
func NewWorkPoolWithFunc(
	workerCount int,
	handler func(interface{}),
	maxBlockingTasks int,
	expiry time.Duration,
	panicHandler func(interface{}),
) (Pool, error) {
	pool, err := ants.NewPoolWithFunc(
		workerCount,
		handler,
		ants.WithPreAlloc(false),
		ants.WithExpiryDuration(expiry),
		ants.WithNonblocking(false),
		ants.WithMaxBlockingTasks(maxBlockingTasks),
		ants.WithPanicHandler(panicHandler),
	)
	if err != nil {
		return nil, err
	}
	return &singlePool{inner: pool}, nil
}

// RulePool 规则评估协程池实例。
type RulePool struct {
	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
	pool       Pool
	stats      RulePoolStats
	curWorkers atomic.Int64 // 总 worker 容量
}

// NewRulePool 创建规则池实例。
//
//   - workerCount: 总 worker 容量
//   - taskHandler: 处理 *RuleTask 的回调
func NewRulePool(workerCount int, taskHandler func(*RuleTask), logs ...logger.Sink) (*RulePool, error) {
	if workerCount <= 0 {
		return nil, fmt.Errorf("rule pool workerCount must be > 0, got %d", workerCount)
	}
	if taskHandler == nil {
		return nil, fmt.Errorf("rule pool taskHandler must not be nil")
	}
	log := logger.Current()
	if len(logs) > 0 && logs[0] != nil {
		log = logs[0]
	}
	rp := &RulePool{}
	rp.curWorkers.Store(int64(workerCount))

	maxBlocking := workerCount * 2
	handler := func(i interface{}) {
		switch task := i.(type) {
		case *RuleTask:
			rp.execute(task, taskHandler, log)
		case *ruleBatch:
			defer releaseRuleBatch(task)
			for _, rule := range task.tasks[:task.count] {
				rp.execute(rule, taskHandler, log)
			}
		default:
			atomic.AddInt64(&rp.stats.FailedTasks, 1)
			log.Error("invalid rule task type")
		}
	}
	p, err := NewWorkPoolWithFunc(
		workerCount,
		handler,
		maxBlocking,
		2*time.Minute,
		func(i interface{}) {
			atomic.AddInt64(&rp.stats.FailedTasks, 1)
			log.Error("规则池goroutine异常: %v", i)
		},
	)
	if err != nil {
		return nil, fmt.Errorf("创建规则池失败: %w", err)
	}
	rp.pool = p
	log.Info("规则池初始化完成，工作线程数: %d", workerCount)
	return rp, nil
}

// execute 按指纹统计并完成内部任务。异常只终止当前指纹，批内其他指纹
// 仍会执行；完成计数先于 WaitGroup，调用方返回时可读取完整统计。
func (rp *RulePool) execute(task *RuleTask, handler func(*RuleTask), log logger.Sink) {
	if task.pooled {
		defer finishRuleTask(task)
	}
	defer func() {
		if failure := recover(); failure != nil {
			atomic.AddInt64(&rp.stats.FailedTasks, 1)
			log.Error("规则池goroutine异常: %v", failure)
		} else {
			atomic.AddInt64(&rp.stats.CompletedTasks, 1)
		}
	}()
	handler(task)
}

func finishRuleTask(task *RuleTask) {
	wg, hook := task.WaitGroup, task.DoneHook
	releaseRuleTask(task)
	if hook != nil {
		hook()
	}
	if wg != nil {
		wg.Done()
	}
}

func (rp *RulePool) submitBatch(batch *ruleBatch) error {
	if rp == nil || rp.closed.Load() || rp.pool == nil {
		return fmt.Errorf("rule pool not initialized")
	}
	count := int64(batch.count)
	if err := rp.pool.Invoke(batch); err != nil {
		return err
	}
	atomic.AddInt64(&rp.stats.TotalTasks, count)
	return nil
}

// Submit 把任务提交到规则池。
func (rp *RulePool) Submit(task *RuleTask) error {
	if rp == nil || rp.closed.Load() || rp.pool == nil {
		return fmt.Errorf("rule pool not initialized")
	}
	if err := rp.pool.Invoke(task); err != nil {
		return err
	}
	atomic.AddInt64(&rp.stats.TotalTasks, 1)
	return nil
}

// Tune 按总 worker 容量下调/上调（内部维持实例总容量）。
func (rp *RulePool) Tune(totalWorkers int) {
	if rp == nil || rp.closed.Load() || rp.pool == nil || totalWorkers <= 0 {
		return
	}
	rp.pool.Tune(totalWorkers)
	rp.curWorkers.Store(int64(totalWorkers))
}

// Release 释放规则池资源（使用 ctx 控制 graceful 退出超时）。
func (rp *RulePool) Release(ctx context.Context) error {
	if rp == nil {
		return nil
	}
	rp.closeOnce.Do(func() {
		rp.closed.Store(true)
		if rp.pool != nil {
			rp.closeErr = rp.pool.Release(ctx)
		}
		rp.curWorkers.Store(0)
	})
	return rp.closeErr
}

// Stats 返回任务统计快照。
func (rp *RulePool) Stats() RulePoolStats {
	if rp == nil {
		return RulePoolStats{}
	}
	return RulePoolStats{
		TotalTasks:     atomic.LoadInt64(&rp.stats.TotalTasks),
		CompletedTasks: atomic.LoadInt64(&rp.stats.CompletedTasks),
		FailedTasks:    atomic.LoadInt64(&rp.stats.FailedTasks),
	}
}

// ResetStats 把统计计数清零。
func (rp *RulePool) ResetStats() {
	if rp == nil {
		return
	}
	atomic.StoreInt64(&rp.stats.TotalTasks, 0)
	atomic.StoreInt64(&rp.stats.CompletedTasks, 0)
	atomic.StoreInt64(&rp.stats.FailedTasks, 0)
}

// CurrentWorkers 当前规则池总 worker 容量。
func (rp *RulePool) CurrentWorkers() int {
	if rp == nil {
		return DefaultRuleWorkers
	}
	return int(rp.curWorkers.Load())
}

// IsClosed 是否已 Release。
func (rp *RulePool) IsClosed() bool { return rp == nil || rp.closed.Load() || rp.pool == nil }

// RuleTask 规则处理任务结构。
type RuleTask struct {
	pooled     bool
	prepared   *cel.PreparedLibrary
	Ctx        context.Context
	Target     string
	Finger     *finger.Finger
	BaseInfo   *BaseInfo
	Proxy      string
	Timeout    time.Duration
	ResultChan chan<- *FingerMatch
	WaitGroup  *sync.WaitGroup
	DoneHook   func()
}
