package sdk_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gcel "github.com/cyberspacesec/gxx/v2/pkg/cel"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/pkg/runner"
	"github.com/cyberspacesec/gxx/v2/sdk"
	celgo "github.com/google/cel-go/cel"
)

func engine(t *testing.T, rules string, opts ...sdk.Option) *sdk.Engine {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.yaml")
	data := "id: audit\ninfo:\n  name: audit\nrules:\n" + rules + "expression: r0()\n"
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	base := []sdk.Option{sdk.WithFingerOptions(sdk.FingerOptions{PocYaml: p}), sdk.WithTimeout(2 * time.Second), sdk.WithRuleConcurrency(8)}
	e, err := sdk.NewEngine(context.Background(), append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}
func oneRule(path string) string {
	return fmt.Sprintf("  r0:\n    request:\n      method: GET\n      path: %s\n    expression: response.status == 200\n", path)
}

func TestRegressionKeepAlive(t *testing.T) {
	var conns atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	s.Start()
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	for i := 0; i < 5; i++ {
		r, err := c.SendRequestHttp(context.Background(), "GET", s.URL, "", network.OptionsRequest{Timeout: time.Second, FollowRedirects: true})
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	t.Logf("5 sequential requests: connections=%d", conns.Load())
	if conns.Load() != 1 {
		t.Errorf("default keep-alive did not reuse the connection")
	}
}

func TestEquivalentGETRequestsShareFlight(t *testing.T) {
	var requests atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/shared" {
			requests.Add(1)
			time.Sleep(60 * time.Millisecond)
		}
		fmt.Fprint(w, "expected")
	}))
	defer s.Close()
	dir := t.TempDir()
	for i := 0; i < 32; i++ {
		body := fmt.Sprintf("id: shared-%d\ninfo:\n  name: 请求合并测试\nrules:\n  r0:\n    request:\n      method: GET\n      path: /shared\n    expression: response.body.bcontains(b'expected')\nexpression: r0()\n", i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.yaml", i)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithRuleConcurrency(32))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	result, err := e.Scan(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) != 32 {
		t.Fatalf("指纹结果缺失: %d", len(result.Matches))
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("重复 GET 次数=%d", got)
	}
}

func TestCachedBatchesPreserveNetworkConcurrencyAndHeaders(t *testing.T) {
	var active, peak atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.Header.Get("X-Shared") != "configured" {
			t.Error("实例请求头缺失")
		}
		if strings.HasPrefix(r.URL.Path, "/slow/") {
			n := active.Add(1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			if r.Header.Get("X-Rule") != "specific" {
				t.Error("规则请求头缺失")
			}
			time.Sleep(10 * time.Millisecond)
			active.Add(-1)
		}
		fmt.Fprint(w, "expected")
	}))
	defer s.Close()
	dir := t.TempDir()
	for i := 0; i < 64; i++ {
		path, headers := "/", ""
		if i%2 == 0 {
			path = fmt.Sprintf("/slow/%d", i)
			headers = "      headers:\n        X-Rule: specific\n"
		}
		body := fmt.Sprintf("id: batch-%d\ninfo:\n  name: 混合调度\nrules:\n  r0:\n    request:\n      method: GET\n      path: %s\n%s    expression: response.body.bcontains(b'expected')\nexpression: r0()\n", i, path, headers)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.yaml", i)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, concurrency := range []int{1, 4} {
		peak.Store(0)
		headers := map[string]string{"X-Shared": "configured"}
		e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithCustomHeaders(headers), sdk.WithRuleConcurrency(concurrency))
		if err != nil {
			t.Fatal(err)
		}
		headers["X-Shared"] = "caller mutation"
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		result, err := e.Scan(ctx, s.URL)
		cancel()
		stats := e.PoolStats()
		e.Close()
		if err != nil || len(result.Matches) != 64 || stats.TotalTasks != 64 || stats.CompletedTasks != 64 {
			t.Fatalf("混合任务结果缺失: concurrency=%d result=%v stats=%+v err=%v", concurrency, result, stats, err)
		}
		if peak.Load() > int64(concurrency) || concurrency == 4 && peak.Load() < 2 {
			t.Fatalf("网络并发预算变化: capacity=%d peak=%d", concurrency, peak.Load())
		}
	}
}

func TestConcurrentSameTargetKeepsOwnResponse(t *testing.T) {
	var roots, barriers atomic.Int64
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			n := roots.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<title>state-%d</title>token=state-%d;", n, n)
		case "/barrier":
			if barriers.Add(1) == 2 {
				close(release)
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer s.Close()
	dir := t.TempDir()
	for i := 1; i <= 2; i++ {
		body := fmt.Sprintf("id: state-%d\ninfo:\n  name: 响应隔离\nrules:\n  r0:\n    request:\n      method: GET\n      path: /barrier\n    expression: 'false'\n  r1:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'token=state-%d;')\nexpression: r1()\n", i, i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.yaml", i)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := e.Scan(context.Background(), s.URL)
			if err != nil {
				t.Error(err)
				return
			}
			if len(result.Matches) != 1 || result.Matches[0].Info.ID != result.Title {
				t.Errorf("扫描响应被其他批次覆盖: title=%q matches=%v", result.Title, result.Matches)
			}
		}()
	}
	wg.Wait()
	if roots.Load() != 2 {
		t.Fatalf("根请求重复: %d", roots.Load())
	}
}

func TestRegressionRateLimit(t *testing.T) {
	var count atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	var rules strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&rules, "  r%d:\n    request:\n      method: GET\n      path: /rule%d\n    expression: response.status == 200\n", i, i)
	}
	e := engine(t, rules.String(), sdk.WithRateLimit(2, 1))
	start := time.Now()
	_, err := e.Scan(context.Background(), s.URL)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("qps=2 burst=1 requests=%d duration=%s", count.Load(), elapsed)
	if count.Load() > 1+int64(2*elapsed.Seconds()) {
		t.Error("request count exceeds rate limit")
	}
}

func TestRegressionCanceledRule(t *testing.T) {
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/slow" {
			close(started)
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	e := engine(t, oneRule("/slow"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-started; cancel() }()
	_, err := e.Scan(ctx, s.URL)
	t.Logf("Scan after in-rule cancellation: %v", err)
	if !errors.Is(err, context.Canceled) {
		t.Error("cancellation did not reach caller")
	}
}

func TestRegressionScanFailure(t *testing.T) {
	e := engine(t, oneRule("/"))
	r, err := e.Scan(context.Background(), "http://[invalid")
	t.Logf("invalid URL: result=%+v err=%v", r, err)
	if err == nil {
		t.Error("invalid target returned success")
	}
	results, err := e.ScanBatch(context.Background(), []string{"", " "})
	t.Logf("empty targets batch: count=%d err=%v", len(results), err)
	if err == nil {
		t.Error("all-failed batch returned success")
	}
}

type countedBody struct {
	r io.Reader
	n int
}

func (c *countedBody) Read(p []byte) (int, error) { n, e := c.r.Read(p); c.n += n; return n, e }
func (c *countedBody) Close() error               { return nil }
func TestRegressionTitleBodyLimit(t *testing.T) {
	b := &countedBody{r: strings.NewReader("<title>audit</title>" + strings.Repeat(" ", 2<<20))}
	req, _ := http.NewRequest("GET", "http://127.0.0.1/", nil)
	resp := &http.Response{Body: b, Request: req, Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	finger.GetTitle(req.URL.String(), resp)
	t.Logf("title body bytes read=%d; documented limit=%d", b.n, network.MaxDefaultBody)
	if int64(b.n) > network.MaxDefaultBody {
		t.Error("title reads body before size cap")
	}
}

func TestRegressionTitleCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/i18n.js" {
			close(started)
			<-release
			fmt.Fprint(w, `"top.login.title": "audit",`)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script type="text/javascript" src="/i18n.js"></script>`)
	}))
	defer s.Close()
	e := engine(t, oneRule("/"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := e.GetBaseInfo(ctx, s.URL); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("i18n request never started")
	}
	cancel()
	select {
	case err := <-done:
		t.Logf("returned %v", err)
	case <-time.After(150 * time.Millisecond):
		t.Error("i18n request still blocks after parent context canceled")
	}
	close(release)

}

func TestRegressionPoolCloseRace(t *testing.T) {
	p, err := runner.NewRulePool(8, func(*runner.RuleTask) {})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = p.IsClosed()
			}
		}
	}()
	_ = p.Release(context.Background())
	close(stop)
	wg.Wait()
}

func TestRegressionWriterResultOwnership(t *testing.T) {
	w, err := sdk.NewFileWriter(filepath.Join(t.TempDir(), "out.json"), sdk.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		r := &sdk.TargetResult{URL: "http://127.0.0.1/", Title: "before"}
		if err := w.Write(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		r.Title = "after"
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRegressionSocketBackpressure(t *testing.T) {
	// 短路径确保 macOS 的 Unix Socket 路径长度限制不干扰验证。
	d, err := os.MkdirTemp("/tmp", "gxxsock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(d)
	path := filepath.Join(d, "s")
	w, err := sdk.NewSockWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Write(ctx, &sdk.TargetResult{Title: strings.Repeat("a", 128<<10)}) }()
	time.Sleep(500 * time.Millisecond)
	blocked := false
	select {
	case err := <-done:
		t.Logf("Write returned: %v", err)
	default:
		blocked = true
		t.Error("slow socket consumer blocked Write after context deadline")
	}
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Error("Close waits on mutex held by blocked Write")
	}
	conn.Close()
	if blocked {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Write did not release")
		}
	}

}

func TestRegressionASTEnvironmentIsolation(t *testing.T) {
	a := gcel.NewCustomLib()
	a.UpdateCompileOption("audit_x", celgo.IntType)
	_, err := a.Evaluate("audit_x + audit_x", map[string]any{"audit_x": int64(2)})
	if err != nil {
		t.Fatal(err)
	}
	b := gcel.NewCustomLib()
	b.UpdateCompileOption("audit_x", celgo.StringType)
	v, err := b.Evaluate("audit_x + audit_x", map[string]any{"audit_x": "x"})
	t.Logf("string environment reused int AST: value=%v err=%v", v, err)
	if err != nil || fmt.Sprint(v) != "xx" {
		t.Error("AST from incompatible declarations reused")
	}
}

func TestRegressionReloadFailure(t *testing.T) {
	e := engine(t, oneRule("/"))
	old := e.FingerCount()
	err := e.LoadFingerOptions(sdk.FingerOptions{PocYaml: filepath.Join(t.TempDir(), "missing.yaml")})
	t.Logf("failed reload: old=%d new=%d err=%v", old, e.FingerCount(), err)
	if e.FingerCount() != old {
		t.Error("failed reload discarded working rules")
	}
}

func BenchmarkRegressionDerivedCEL(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := gcel.NewCustomLib()
		c.PreRegisterRuleFunctions([]string{"r0"})
		c.WriteRuleFunctionsROptions("r0", true)
		_, err := c.Evaluate("r0()", nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkRegressionBaseCEL(b *testing.B) {
	c := gcel.NewCustomLib()
	_, _ = c.Evaluate("true", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := c.Evaluate("true", nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestRegressionMonitorRestartRace(t *testing.T) {
	p := runner.NewPerformanceMonitor(1<<30, 2<<30, nil)
	for i := 0; i < 12; i++ {
		p.Start()
		p.Stop()
	}
}

func TestRegressionPureTCPRulesSkipped(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	rules := "  r0:\n    request:\n      type: tcp\n      host: " + strings.TrimPrefix(s.URL, "http://") + "\n      data: ping\n    expression: true\n"
	e := engine(t, rules)
	_, err := e.Scan(context.Background(), strings.TrimPrefix(s.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("loaded=%d scheduled=%d", e.FingerCount(), e.PoolStats().TotalTasks)
	if e.PoolStats().TotalTasks == 0 {
		t.Error("TCP rules were pruned after forced HTTP discovery")
	}
}

func TestRegressionRawRequestCacheCollision(t *testing.T) {
	var rawCalls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/raw-only" {
			rawCalls.Add(1)
		}
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	rules := "  r0:\n    request:\n      method: GET\n      path: /\n      raw: |\n        GET /raw-only HTTP/1.1\n        Host: " + strings.TrimPrefix(s.URL, "http://") + "\n\n    expression: response.status == 200\n"
	e := engine(t, rules)
	r, err := e.Scan(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("raw endpoint calls=%d matches=%d", rawCalls.Load(), len(r.Matches))
	if rawCalls.Load() == 0 {
		t.Error("raw HTTP rule reused unrelated baseline response")
	}
}

func TestRegressionRandomNotConstant(t *testing.T) {
	values := map[string]bool{}
	for i := 0; i < 8; i++ {
		c := gcel.NewCustomLib()
		v, err := c.Evaluate("randomInt(1, 10000000)", nil)
		if err != nil {
			t.Fatal(err)
		}
		values[fmt.Sprint(v)] = true
	}
	t.Logf("distinct random values=%d", len(values))
	if len(values) == 1 {
		t.Error("random function constant-folded across evaluations")
	}
}

func TestRegressionEngineConcurrencyBudget(t *testing.T) {
	var active, peak atomic.Int64
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	e := engine(t, oneRule("/"), sdk.WithURLConcurrency(1))
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() { defer wg.Done(); _, _ = e.ScanBatch(context.Background(), []string{s.URL}) }()
	}
	<-started
	select {
	case <-started:
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	t.Logf("WithURLConcurrency(1), concurrent batches: peak requests=%d", peak.Load())
	if peak.Load() > 1 {
		t.Error("concurrency setting applies per batch, not per Engine")
	}
}
func TestRegressionDefaultRulesOutsideRepo(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	e, err := sdk.NewEngine(context.Background())
	if e != nil {
		e.Close()
	}
	t.Logf("NewEngine outside repository: %v", err)
	if err != nil {
		t.Error("default build does not provide documented embedded rule fallback")
	}
}

func TestMixedLibraryStillRunsTCPAfterHTTPFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 4096)
				if _, err := conn.Read(buffer); err == nil {
					conn.Write([]byte("pong"))
				}
			}()
		}
	}()
	dir := t.TempDir()
	files := map[string]string{
		"http": oneRule("/"),
		"tcp":  "  r0:\n    request:\n      type: tcp\n      data: ping\n    expression: response.raw.bcontains(b\"pong\")\n",
	}
	for name, rules := range files {
		data := "id: " + name + "\ninfo:\n  name: " + name + "\nrules:\n" + rules + "expression: r0()\n"
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithTimeout(250*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := e.Scan(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Matches) != 1 || result.Matches[0].Info.ID != "tcp" {
		t.Fatalf("TCP 指纹未命中: %+v", result.Matches)
	}
}
