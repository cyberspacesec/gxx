package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 多个引擎、每个引擎被多个 goroutine 同时调用时，结果不能串到别的目标上：
// 标题、Cookie 会话、跳转链、命中的指纹都必须属于各自的目标。
func TestConcurrentScansStayIsolated(t *testing.T) {
	const servers, engines, rounds = 6, 3, 40
	// 最先注册、最后执行：此时引擎与靶场都已关闭，不应残留后台 goroutine。
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		http.DefaultClient.CloseIdleConnections()
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > before+4 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > before+4 {
			buf := make([]byte, 1<<20)
			t.Errorf("goroutine 泄漏: 扫描前 %d，关闭后 %d\n%s", before, n, buf[:runtime.Stack(buf, true)])
		}
	})
	var cookieLeak atomic.Int64
	urls := make([]string, servers)
	for i := range urls {
		id := fmt.Sprintf("site-%d", i)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 每个站点只接受自己发出的 Cookie；见到别的值说明会话串了。
			if c, err := r.Cookie("owner"); err == nil && c.Value != id {
				cookieLeak.Add(1)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			switch r.URL.Path {
			case "/":
				http.SetCookie(w, &http.Cookie{Name: "owner", Value: id, Path: "/"})
				http.Redirect(w, r, "/home", http.StatusFound)
			case "/home":
				if c, err := r.Cookie("owner"); err != nil || c.Value != id {
					fmt.Fprint(w, "<title>no-session</title>")
					return
				}
				fmt.Fprintf(w, "<html><head><title>%s</title></head><body>marker-%s %s</body></html>", id, id, strings.Repeat("x", 6000))
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	rules := map[string]string{}
	for i := 0; i < servers; i++ {
		rules[fmt.Sprintf("site-%d", i)] = rootRule(fmt.Sprintf(`response.body.bcontains(b"marker-site-%d ")`, i))
	}
	rules["entry"] = rootRule(`response.status == 302`)

	var wg sync.WaitGroup
	var failures atomic.Int64
	for e := 0; e < engines; e++ {
		engine := ruleLibrary(t, rules)
		for n := 0; n < rounds; n++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				i := n % servers
				want := fmt.Sprintf("site-%d", i)
				result, err := engine.Scan(context.Background(), urls[i])
				if err != nil {
					failures.Add(1)
					t.Errorf("%s: %v", want, err)
					return
				}
				ids := matchedIDs(result)
				if result.Title != want || result.FinalURL != urls[i]+"/home" || len(ids) != 2 || ids[0] != "entry" || ids[1] != want {
					failures.Add(1)
					t.Errorf("%s 的结果串了: title=%q final=%q matches=%v", want, result.Title, result.FinalURL, ids)
				}
			}(n)
		}
	}
	wg.Wait()
	if cookieLeak.Load() != 0 {
		t.Fatalf("Cookie 会话串到了其他站点 %d 次", cookieLeak.Load())
	}
	if failures.Load() != 0 {
		t.FailNow()
	}
}
