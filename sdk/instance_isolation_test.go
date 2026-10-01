package sdk_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/sdk"
	"github.com/cyberspacesec/gxx/utils/common"
)

type isolatedWriter struct {
	mu      sync.Mutex
	results []*sdk.TargetResult
	closed  atomic.Bool
}

func TestOverlappingEnginesKeepTLSVerificationPolicy(t *testing.T) {
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<title>TLS target</title>")
	}))
	secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	secure.StartTLS()
	defer secure.Close()
	started, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, "<title>first instance</title>")
	}))
	defer plain.Close()
	rules := "  r0:\n    request:\n      method: GET\n      path: /hold\n    expression: true\n"
	a := engine(t, rules, sdk.WithInsecureSkipVerify(false), sdk.WithURLConcurrency(2))
	done := make(chan isolationResult, 1)
	go func() { result, err := a.Scan(context.Background(), plain.URL); done <- isolationResult{result, err} }()
	waitIsolationPoint(t, started)
	b := engine(t, "  r0:\n    request:\n      method: GET\n      path: /\n    expression: true\n", sdk.WithInsecureSkipVerify(true))
	if result, err := b.GetBaseInfo(context.Background(), secure.URL); err != nil || result.Title != "TLS target" {
		t.Fatalf("第二实例未使用自己的 TLS 策略: result=%+v err=%v", result, err)
	}
	if _, err := a.GetBaseInfo(context.Background(), secure.URL); err == nil {
		t.Fatal("第二实例覆盖了第一实例的 TLS 证书校验策略")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	unblock()
	select {
	case first := <-done:
		if first.err != nil || len(first.result.Matches) != 1 {
			t.Fatalf("第二实例的 TLS 设置或关闭影响了首个扫描: %+v", first)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("首个实例没有完成扫描")
	}
}

func (w *isolatedWriter) Write(_ context.Context, r *sdk.TargetResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed.Load() {
		return fmt.Errorf("输出实例提前关闭")
	}
	w.results = append(w.results, r)
	return nil
}
func (w *isolatedWriter) Close() error { w.closed.Store(true); return nil }
func (w *isolatedWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.results)
}

func isolatedEngine(t *testing.T, yaml string, options ...sdk.Option) *sdk.Engine {
	t.Helper()
	file := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	base := []sdk.Option{sdk.WithFingerOptions(sdk.FingerOptions{PocYaml: file}), sdk.WithRuleConcurrency(2), sdk.WithTimeout(5 * time.Second)}
	e, err := sdk.NewEngine(context.Background(), append(base, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func waitIsolationPoint(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("扫描没有到达实例隔离检查点")
	}
}

type isolationResult struct {
	result *sdk.TargetResult
	err    error
}

func TestEngineCreatedDuringScanCannotShareFaviconContent(t *testing.T) {
	firstImage, secondImage := []byte("first SDK icon"), []byte("second SDK icon")
	firstHash := strconv.FormatInt(int64(common.Mmh3Hash32(finger.StandBase64(firstImage))), 10)
	secondHash := strconv.FormatInt(int64(common.Mmh3Hash32(finger.StandBase64(secondImage))), 10)
	var phase, images atomic.Int64
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "first SDK rule")
		case "/favicon.ico":
			images.Add(1)
			w.Header().Set("Content-Type", "image/png")
			if phase.Load() == 0 {
				w.Write(firstImage)
			} else {
				w.Write(secondImage)
			}
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><title>same target</title><link rel='icon' href='/favicon.ico'></html>")
		}
	}))
	defer s.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	firstRules := fmt.Sprintf("id: first\ninfo:\n  name: first\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.icon_hash == '%s'\n  r1:\n    request:\n      method: GET\n      path: /hold\n    expression: response.body.bcontains(b'first SDK rule')\nexpression: r0() && r1()\n", firstHash)
	a := isolatedEngine(t, firstRules)
	done := make(chan isolationResult, 1)
	go func() { result, err := a.Scan(context.Background(), s.URL); done <- isolationResult{result, err} }()
	waitIsolationPoint(t, started)
	phase.Store(1)
	b := engine(t, fmt.Sprintf("  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.icon_hash == '%s'\n", secondHash))
	result, err := b.Scan(context.Background(), s.URL)
	if err != nil || len(result.Matches) != 1 || images.Load() != 2 {
		t.Fatalf("第二个 SDK 复用了第一个的图标: result=%+v err=%v iconRequests=%d", result, err, images.Load())
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	// 失败路径同样释放服务端等待，避免用例留下阻塞连接。
	unblock()
	select {
	case first := <-done:
		if first.err != nil || len(first.result.Matches) != 1 || first.result.Matches[0].Info.ID != "first" {
			t.Fatalf("构造或关闭第二个 SDK 影响了首个扫描: %+v", first)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("关闭第二个 SDK 后首个扫描未完成")
	}
}

func TestOverlappingEnginesIsolateHeadersCookiesRulesWritersAndCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		instance := r.Header.Get("X-Instance")
		if instance != "A" && instance != "B" {
			t.Errorf("请求头被调用方或其他实例覆盖: %q", instance)
		}
		if r.URL.Path == "/hold" && instance == "A" {
			once.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		if r.URL.Path == "/favicon.ico" {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != instance {
				t.Errorf("CookieJar 跨实例串用: instance=%s cookie=%v err=%v", instance, cookie, err)
			}
			w.Header().Set("Content-Type", "image/png")
			fmt.Fprint(w, instance)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: instance, Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><title>%s</title><body>%s</body></html>", instance, instance)
	}))
	defer s.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	wa, wb := &isolatedWriter{}, &isolatedWriter{}
	headers := map[string]string{"X-Instance": "A"}
	a := engine(t, "  r0:\n    request:\n      method: GET\n      path: /hold\n    expression: response.body.bcontains(b'A')\n", sdk.WithCustomHeaders(headers), sdk.WithWriter(wa), sdk.WithTimeout(5*time.Second), sdk.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	done := make(chan isolationResult, 1)
	go func() { result, err := a.Scan(context.Background(), s.URL); done <- isolationResult{result, err} }()
	waitIsolationPoint(t, started)
	headers["X-Instance"] = "B"
	b := engine(t, "  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'B')\n", sdk.WithCustomHeaders(headers), sdk.WithWriter(wb), sdk.WithTimeout(time.Second), sdk.WithDisableKeepAlives(true), sdk.WithDebug(true), sdk.WithLogger(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	ctx, cancel := context.WithCancel(context.Background())
	result, err := b.Scan(ctx, s.URL)
	if err != nil || result.Title != "B" || len(result.Matches) != 1 {
		t.Fatalf("第二个实例未使用自己的配置: result=%+v err=%v", result, err)
	}
	cancel()
	if err := b.Close(); err != nil || wa.closed.Load() || !wb.closed.Load() {
		t.Fatalf("关闭第二个实例影响首个输出: err=%v", err)
	}
	unblock()
	select {
	case first := <-done:
		if first.err != nil || first.result.Title != "A" || len(first.result.Matches) != 1 || wa.count() != 1 || wb.count() != 1 {
			t.Fatalf("实例状态串用: first=%+v writers=%d/%d", first, wa.count(), wb.count())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("首个实例被第二个实例的取消或关闭影响")
	}
}

func TestReverseConfigIsOwnedByEachOverlappingEngine(t *testing.T) {
	for _, jndi := range []bool{false, true} {
		t.Run(strconv.FormatBool(jndi), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var callsA, callsB atomic.Int64
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := r.Header.Get("X-Instance")
				query := r.URL.Query()
				if query.Get("api") == "" && query.Get("token") == "" {
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, "ok")
					return
				}
				if key == "A" {
					callsA.Add(1)
					once.Do(func() { close(started) })
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				} else {
					callsB.Add(1)
				}
				if !jndi {
					if query.Get("token") != key+"+secret" || len(query.Get("filter")) != 12 {
						t.Errorf("Ceye 实例配置被覆盖: %s %s", key, r.URL)
					}
					fmt.Fprint(w, `{"code": 200, "data": ["found"]}`)
				} else {
					if query.Get("api") == "" || r.Host != strings.ToLower(key)+".reverse.example.com:"+map[string]string{"A": "12301", "B": "12302"}[key] {
						t.Errorf("JNDI 实例配置被覆盖: %s %s", key, r.URL)
					}
					fmt.Fprint(w, "yes")
				}
			}))
			defer api.Close()
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "ok")
			}))
			defer target.Close()
			makeEngine := func(instance string) *sdk.Engine {
				config := sdk.ReverseConfig{CeyeAPIKey: instance + "+secret", CeyeDomain: strings.ToLower(instance) + ".example.com", JNDIHost: strings.ToLower(instance) + ".reverse.example.com", LDAPPort: "1389", APIPort: map[string]string{"A": "12301", "B": "12302"}[instance]}
				set, expression := "newReverse()", "reverse.wait(0)"
				if jndi {
					set, expression = "newJNDI()", "reverse.jndi(0)"
				}
				yaml := fmt.Sprintf("id: reverse-%s\nset:\n  reverse: %s\ninfo:\n  name: reverse\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: %s\nexpression: r0()\n", instance, set, expression)
				return isolatedEngine(t, yaml, sdk.WithReverseConfig(config), sdk.WithProxy(api.URL), sdk.WithCustomHeaders(map[string]string{"X-Instance": instance}))
			}
			a := makeEngine("A")
			done := make(chan isolationResult, 1)
			go func() { result, err := a.Scan(context.Background(), target.URL); done <- isolationResult{result, err} }()
			waitIsolationPoint(t, started)
			b := makeEngine("B")
			second, err := b.Scan(context.Background(), target.URL)
			if err != nil || len(second.Matches) != 1 || callsB.Load() != 1 {
				t.Fatalf("第二个实例反连查询失败: result=%+v err=%v calls=%d", second, err, callsB.Load())
			}
			b.Close()
			unblock()
			select {
			case first := <-done:
				if first.err != nil || len(first.result.Matches) != 1 || callsA.Load() != 1 {
					t.Fatalf("首个实例反连配置被覆盖: %+v calls=%d", first, callsA.Load())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("首个反连查询未完成")
			}
		})
	}
}
