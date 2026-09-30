package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
	"github.com/cyberspacesec/gxx/utils/logger"
)

func newTestHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "gxx-test/1.0")
		_, _ = w.Write([]byte("<html><head><title>gxx-test</title></head><body>ok</body></html>"))
	}))
}

// TestEngine_NewEngineEmbedded 验证用嵌入指纹库初始化 Engine。
func TestEngine_NewEngineEmbedded(t *testing.T) {
	ctx := context.Background()
	engine, err := sdk.NewEngine(ctx,
		sdk.WithTimeout(5*time.Second),
		sdk.WithRuleConcurrency(50),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	if engine.IsClosed() {
		t.Fatalf("expected engine not closed after NewEngine")
	}
	if engine.FingerCount() == 0 {
		t.Fatalf("expected fingers loaded > 0")
	}

	stats := engine.PoolStats()
	if stats.TotalTasks < 0 {
		t.Fatalf("invalid pool stats: %+v", stats)
	}
}

// TestEngine_WithDebug 调试实例不改变进程中的全局日志级别。
func TestEngine_WithDebug(t *testing.T) {
	prev := logger.ActiveLogLevel()
	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(3*time.Second),
		sdk.WithRuleConcurrency(20),
		sdk.WithDebug(true),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if logger.ActiveLogLevel() != prev {
		t.Fatalf("WithDebug changed the global log level: %v", logger.ActiveLogLevel())
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if logger.ActiveLogLevel() != prev {
		t.Fatalf("expected log level restored to %v after Close, got %v", prev, logger.ActiveLogLevel())
	}
}

// TestEngine_CloseIdempotent 关闭多次不应 panic。
func TestEngine_CloseIdempotent(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("first Close error: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
	if !engine.IsClosed() {
		t.Fatalf("expected IsClosed=true after Close")
	}
}

// TestEngine_ScanAfterClose 关闭后扫描应返回 ErrEngineClosed。
func TestEngine_ScanAfterClose(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	_ = engine.Close()

	_, err = engine.Scan(context.Background(), "https://example.com")
	if !errors.Is(err, sdk.ErrEngineClosed) {
		t.Fatalf("expected ErrEngineClosed, got: %v", err)
	}

	_, err = engine.GetBaseInfo(context.Background(), "https://example.com")
	if !errors.Is(err, sdk.ErrEngineClosed) {
		t.Fatalf("expected ErrEngineClosed, got: %v", err)
	}
}

// TestEngine_EmptyTarget 验证 sentinel error。
func TestEngine_EmptyTarget(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	_, err = engine.Scan(context.Background(), "")
	if !errors.Is(err, sdk.ErrEmptyTarget) {
		t.Fatalf("expected ErrEmptyTarget, got: %v", err)
	}

	_, err = engine.GetBaseInfo(context.Background(), "")
	if !errors.Is(err, sdk.ErrEmptyTarget) {
		t.Fatalf("expected ErrEmptyTarget, got: %v", err)
	}
}

// TestEngine_InvalidOption 验证 ErrInvalidOption 包装。
func TestEngine_InvalidOption(t *testing.T) {
	_, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(0),
	)
	if !errors.Is(err, sdk.ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for timeout=0, got: %v", err)
	}

	_, err = sdk.NewEngine(context.Background(),
		sdk.WithRuleConcurrency(-1),
	)
	if !errors.Is(err, sdk.ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for concurrency<0, got: %v", err)
	}

	_, err = sdk.NewEngine(context.Background(),
		sdk.WithCacheSize(0),
	)
	if !errors.Is(err, sdk.ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for cacheSize=0, got: %v", err)
	}
}

// TestEngine_ConcurrentEngines 验证多 Engine 并发隔离。
func TestEngine_ConcurrentEngines(t *testing.T) {
	const N = 4
	engines := make([]*sdk.Engine, N)
	for i := 0; i < N; i++ {
		e, err := sdk.NewEngine(context.Background(),
			sdk.WithTimeout(3*time.Second),
			sdk.WithRuleConcurrency(50),
		)
		if err != nil {
			t.Fatalf("NewEngine[%d] failed: %v", i, err)
		}
		engines[i] = e
	}
	defer func() {
		for _, e := range engines {
			_ = e.Close()
		}
	}()

	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func(eng *sdk.Engine) {
			defer wg.Done()
			if eng.FingerCount() == 0 {
				t.Errorf("engine should have fingers loaded")
			}
		}(e)
	}
	wg.Wait()
}

// TestEngine_ScanCallback 验证流式回调（本地 httptest，不依赖外网）。
func TestEngine_ScanCallback(t *testing.T) {
	srv := newTestHTTPServer(t)
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(3*time.Second),
		sdk.WithRuleConcurrency(50),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	targets := []string{srv.URL}
	var mu sync.Mutex
	var got []string

	cb := func(r *sdk.TargetResult) bool {
		mu.Lock()
		got = append(got, r.URL)
		mu.Unlock()
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := engine.ScanCallback(ctx, targets, cb); err != nil {
		t.Fatalf("ScanCallback unexpected err: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("expected at least one callback for local server, got 0")
	}
	if len(got) > len(targets) {
		t.Fatalf("callback called more than targets: got=%d targets=%d", len(got), len(targets))
	}
}

// TestEngine_NormalizeURL 验证 URL 规范化（本地 httptest）。
func TestEngine_NormalizeURL(t *testing.T) {
	srv := newTestHTTPServer(t)
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(3*time.Second),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	for _, target := range []string{srv.URL, "http://" + strings.TrimPrefix(srv.URL, "http://")} {
		got, err := engine.NormalizeURL(ctx, target)
		if err != nil {
			t.Fatalf("NormalizeURL(%q) err=%v", target, err)
		}
		if !strings.HasPrefix(got, "http://") && !strings.HasPrefix(got, "https://") {
			t.Fatalf("expected http(s)://... got: %s", got)
		}
	}
}

// TestEngine_TimeoutSubsecond 验证亚秒级 WithTimeout 不会被截断为 0 秒。
func TestEngine_TimeoutSubsecond(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("slow"))
	}))
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(500*time.Millisecond),
		sdk.WithRuleConcurrency(10),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	start := time.Now()
	_, _ = engine.Scan(context.Background(), srv.URL)
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("expected ~500ms client timeout, took %v", elapsed)
	}
}

// TestEngine_ScanCallbackCancel 验证 callback 返回 false 后不再扫描后续目标。
func TestEngine_ScanCallbackCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("<html><title>t</title></html>"))
	}))
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(2*time.Second),
		sdk.WithURLConcurrency(1),
		sdk.WithRuleConcurrency(10),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	targets := []string{srv.URL, srv.URL, srv.URL}
	var callbacks atomic.Int32

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = engine.ScanCallback(ctx, targets, func(*sdk.TargetResult) bool {
		callbacks.Add(1)
		return false
	})
	if err != nil {
		t.Fatalf("ScanCallback err: %v", err)
	}
	if callbacks.Load() != 1 {
		t.Fatalf("expected exactly 1 callback before cancel, got %d", callbacks.Load())
	}
}

// TestEngine_ScanCallbackCancelConcurrent 高并发下 callback=false 后不应再触发回调。
func TestEngine_ScanCallbackCancelConcurrent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("<html><title>t</title></html>"))
	}))
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(2*time.Second),
		sdk.WithURLConcurrency(3),
		sdk.WithRuleConcurrency(20),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	targets := make([]string, 6)
	for i := range targets {
		targets[i] = srv.URL
	}

	var callbacks atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := engine.ScanCallback(ctx, targets, func(*sdk.TargetResult) bool {
		callbacks.Add(1)
		return false
	}); err != nil {
		t.Fatalf("ScanCallback err: %v", err)
	}
	if callbacks.Load() != 1 {
		t.Fatalf("expected exactly 1 callback under concurrent cancel, got %d", callbacks.Load())
	}
}

// TestEngine_NormalizeURLNoSchemeTimeout 无 scheme 目标的协议探测应遵守 WithTimeout。
func TestEngine_NormalizeURLNoSchemeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	engine, err := sdk.NewEngine(context.Background(), sdk.WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	start := time.Now()
	_, err = engine.NormalizeURL(context.Background(), host)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected protocol probe timeout error")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("expected ~200ms probe timeout, took %v", elapsed)
	}
}

// TestEngine_OptionFunctional 验证 functional options 链式工作。
func TestEngine_OptionFunctional(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeoutSeconds(8),
		sdk.WithProxy(""),
		sdk.WithRuleConcurrency(100),
		sdk.WithURLConcurrency(3),
		sdk.WithCacheSize(1024),
		sdk.WithCacheTTL(5*time.Minute),
		sdk.WithRateLimit(50, 100),
		sdk.WithDisableKeepAlives(false),
		sdk.WithProactiveGC(false),
		sdk.WithMemoryThresholds(1<<30, 2<<30),
		sdk.WithCustomHeaders(map[string]string{"X-Test": "1"}),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()
}
