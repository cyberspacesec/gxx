package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// multiPathEngine 的规则库对每个目标发出 1 个入口请求和 paths 个不同路径的规则请求。
func multiPathEngine(t *testing.T, paths int, opts ...sdk.Option) *sdk.Engine {
	t.Helper()
	dir := t.TempDir()
	data := "id: paths\ninfo:\n  name: paths\nrules:\n"
	for i := 0; i < paths; i++ {
		data += fmt.Sprintf("  r%d:\n    request:\n      method: GET\n      path: /p%d\n    expression: response.status == 200\n", i, i)
	}
	data += "expression: r0()\n"
	if err := os.WriteFile(filepath.Join(dir, "paths.yaml"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := sdk.NewEngine(context.Background(), append([]sdk.Option{sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithTimeout(20 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// scanRate 并发扫描 targets 个本机服务，返回请求总数与耗时。
func scanRate(t *testing.T, e *sdk.Engine, targets int) (int64, time.Duration) {
	t.Helper()
	var hits atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < targets; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			fmt.Fprint(w, "ok")
		}))
		t.Cleanup(srv.Close)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Scan(context.Background(), srv.URL); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	return hits.Load(), time.Since(start)
}

// 总速率限制约束的是引擎发出的全部请求，不随并发目标数放大。
func TestGlobalRateLimitBoundsTotalRequests(t *testing.T) {
	e := multiPathEngine(t, 20, sdk.WithGlobalRateLimit(40, 1), sdk.WithURLConcurrency(4))
	requests, elapsed := scanRate(t, e, 4)
	if requests != 4*21 {
		t.Fatalf("请求数=%d", requests)
	}
	// 84 个请求按 40 次/秒至少需要约 2.07 秒；留出计时误差。
	if rate := float64(requests) / elapsed.Seconds(); rate > 44 || elapsed < 1900*time.Millisecond {
		t.Fatalf("总速率 %.1f 次/秒超过上限 40（耗时 %v）", rate, elapsed)
	}
}

// 每分钟的写法换算为匀速发出：600 次/分钟即 10 次/秒。
func TestGlobalRatePerMinute(t *testing.T) {
	e := multiPathEngine(t, 14, sdk.WithGlobalRatePerMinute(600))
	requests, elapsed := scanRate(t, e, 1)
	if requests != 15 || elapsed < 1300*time.Millisecond {
		t.Fatalf("15 个请求按 600 次/分钟至少需要约 1.4 秒: requests=%d elapsed=%v", requests, elapsed)
	}
}

// 每主机限速按主机名或 IP 计，不区分端口：同一台主机上的多个资产共用一个令牌桶。
func TestHostRateLimitSharedAcrossPorts(t *testing.T) {
	e := multiPathEngine(t, 9, sdk.WithRateLimit(20, 1), sdk.WithURLConcurrency(3))
	// 三个服务都在 127.0.0.1 的不同端口上，共 30 个请求。
	requests, elapsed := scanRate(t, e, 3)
	if requests != 30 || elapsed < 1300*time.Millisecond {
		t.Fatalf("30 个请求按每主机 20 次/秒至少需要约 1.45 秒: requests=%d elapsed=%v", requests, elapsed)
	}
}

func TestRateLimitOptionsValidate(t *testing.T) {
	for _, opt := range []sdk.Option{sdk.WithGlobalRateLimit(0, 1), sdk.WithGlobalRateLimit(1, 0), sdk.WithGlobalRatePerMinute(0), sdk.WithRateLimit(-1, 1)} {
		if e, err := sdk.NewEngine(context.Background(), opt); err == nil {
			_ = e.Close()
			t.Fatal("无效的限速参数应被拒绝")
		}
	}
}

// 打开按端口限速后，同一台主机的每个端口各有一个令牌桶，互不等待。
func TestHostRateLimitPerPort(t *testing.T) {
	e := multiPathEngine(t, 9, sdk.WithRateLimit(20, 1), sdk.WithRateLimitPerPort(true), sdk.WithURLConcurrency(3))
	// 三个端口各 10 个请求：每个端口约 0.45 秒，并发进行；合并计算时需要约 1.45 秒。
	requests, elapsed := scanRate(t, e, 3)
	if requests != 30 || elapsed < 400*time.Millisecond || elapsed > 1400*time.Millisecond {
		t.Fatalf("按端口限速时 3 个端口应并行、各自不超过 20 次/秒: requests=%d elapsed=%v", requests, elapsed)
	}
}
