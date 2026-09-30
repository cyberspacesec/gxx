// Package lifecycle 管理实例准入、在途操作和统一关闭。
package lifecycle

import (
	"context"
	"errors"
	"sync"
)

var ErrClosed = errors.New("实例已经关闭")

type Gate struct {
	mu     sync.Mutex
	closed bool
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	err    error
	slots  chan struct{}
}

func New(concurrency int) *Gate {
	ctx, cancel := context.WithCancel(context.Background())
	g := &Gate{ctx: ctx, cancel: cancel}
	if concurrency > 0 {
		g.slots = make(chan struct{}, concurrency)
	}
	return g
}

// Begin 在关闭开始前登记操作。释放函数必须在资源使用结束后调用。
func (g *Gate) Begin(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, nil, ErrClosed
	}
	g.wg.Add(1)
	g.mu.Unlock()
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(g.ctx, cancel)
	acquired := false
	release := func() {
		if acquired {
			<-g.slots
		}
		stop()
		cancel()
		g.wg.Done()
	}
	if g.slots != nil {
		select {
		case g.slots <- struct{}{}:
			acquired = true
		case <-ctx.Done():
			release()
			return nil, nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, nil, err
	}
	return ctx, release, nil
}

func (g *Gate) Close(cleanup func() error) error {
	g.once.Do(func() {
		g.mu.Lock()
		g.closed = true
		g.cancel()
		g.mu.Unlock()
		g.wg.Wait()
		g.err = cleanup()
	})
	return g.err
}
