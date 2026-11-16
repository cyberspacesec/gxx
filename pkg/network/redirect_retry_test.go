package network

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 重定向只在同一资产（协议 + 主机 + 端口）内跟随：指向其他资产时返回 30x 响应本身，
// 不向对方发出任何请求，自定义请求头也就不可能泄漏。
func TestRedirectsStayWithinAsset(t *testing.T) {
	var foreignHits atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		_, _ = io.WriteString(w, "foreign")
	}))
	defer foreign.Close()

	type seen struct{ method, body, token string }
	requests := make(chan seen, 8)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/cross":
			http.Redirect(w, r, foreign.URL+"/landing", http.StatusFound)
		case "/same", "/post302":
			http.Redirect(w, r, "/dest", http.StatusFound)
		case "/post307":
			http.Redirect(w, r, "/dest", http.StatusTemporaryRedirect)
		case "/loop":
			http.Redirect(w, r, "/loop?n="+r.URL.Query().Get("n")+"x", http.StatusFound)
		case "/dest":
			requests <- seen{r.Method, string(body), r.Header.Get("X-Api-Token")}
			_, _ = io.WriteString(w, "dest")
		}
	}))
	defer origin.Close()

	client := NewHTTPClient()
	defer client.Close()
	opts := OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true, CustomHeaders: map[string]string{"X-Api-Token": "secret"}}
	send := func(method, path, body string) *http.Response {
		t.Helper()
		resp, err := client.SendRequestHttp(context.Background(), method, origin.URL+path, body, opts)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}

	resp := send(http.MethodGet, "/cross", "")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != foreign.URL+"/landing" {
		t.Fatalf("跨资产跳转应停在 30x: status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if foreignHits.Load() != 0 {
		t.Fatalf("向其他资产发出了 %d 次请求", foreignHits.Load())
	}

	if resp = send(http.MethodGet, "/same", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("同资产跳转应跟随: %d", resp.StatusCode)
	}
	if got := <-requests; got.token != "secret" {
		t.Fatalf("同资产跳转应保留自定义头: %+v", got)
	}
	// 302 之后改为不带请求体的 GET；307 保持方法与请求体。
	send(http.MethodPost, "/post302", "a=1")
	if got := <-requests; got.method != http.MethodGet || got.body != "" {
		t.Fatalf("302 之后的请求: %+v", got)
	}
	send(http.MethodPost, "/post307", "a=1")
	if got := <-requests; got.method != http.MethodPost || got.body != "a=1" {
		t.Fatalf("307 之后的请求: %+v", got)
	}
	// 跳转回环在上限处停下，返回最后一个 30x 而不是错误。
	if resp = send(http.MethodGet, "/loop", ""); resp.StatusCode != http.StatusFound {
		t.Fatalf("回环应返回最后的 30x: %d", resp.StatusCode)
	}
}

// Cookie 会话属于 ctx：同一会话内前一个请求设置的 Cookie 会带到后续请求（无论是否
// 跟随重定向），不同会话互不可见。
func TestCookieSessionScopedToContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc", Path: "/"})
			http.Redirect(w, r, "/home", http.StatusFound)
			return
		}
		cookie, _ := r.Cookie("sid")
		if cookie == nil {
			_, _ = io.WriteString(w, "anonymous")
			return
		}
		_, _ = io.WriteString(w, "user:"+cookie.Value)
	}))
	defer srv.Close()
	client := NewHTTPClient()
	defer client.Close()
	get := func(ctx context.Context, path string, follow bool) string {
		t.Helper()
		resp, err := client.SendRequestHttp(ctx, http.MethodGet, srv.URL+path, "", OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: follow})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	scan := WithCookieJar(context.Background())
	if got := get(scan, "/login", true); got != "user:abc" {
		t.Fatalf("跳转链内应携带刚设置的 Cookie: %q", got)
	}
	if got := get(scan, "/home", false); got != "user:abc" {
		t.Fatalf("同一会话中不跟随重定向的请求也应携带 Cookie: %q", got)
	}
	if got := get(WithCookieJar(context.Background()), "/home", true); got != "anonymous" {
		t.Fatalf("其他会话不应看到 Cookie: %q", got)
	}
	if got := get(context.Background(), "/home", true); got != "anonymous" {
		t.Fatalf("没有会话的独立请求不应看到 Cookie: %q", got)
	}
}

// N1：关闭端口必须快速失败，而不是重试到整体超时。
func TestClosedPortFailsFasterThanTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	client := NewHTTPClient()
	defer client.Close()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		start := time.Now()
		_, err := client.SendRequestHttp(context.Background(), method, "http://"+closed+"/", "", OptionsRequest{Timeout: 5 * time.Second, FollowRedirects: false})
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("%s 连接关闭端口应失败", method)
		}
		// 1 次重试 + 最大 600ms 退避，远小于 5s 超时；放宽到 2s 容忍 CI 抖动。
		if elapsed > 2*time.Second {
			t.Errorf("%s 关闭端口耗时 %v，疑似重试到超时", method, elapsed)
		}
	}
}
