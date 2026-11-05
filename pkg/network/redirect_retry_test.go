package network

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// S5：跨源重定向必须剥离自定义请求头，避免敏感头泄漏给第三方；同源重定向保留。
func TestCustomHeadersStrippedOnCrossOriginRedirect(t *testing.T) {
	var mu sync.Mutex
	thirdPartyGot := map[string]string{}
	thirdParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landing" {
			mu.Lock()
			thirdPartyGot["X-Api-Token"] = r.Header.Get("X-Api-Token")
			thirdPartyGot["User-Agent-Present"] = boolStr(r.Header.Get("User-Agent") != "")
			mu.Unlock()
		}
		_, _ = io.WriteString(w, "landing")
	}))
	defer thirdParty.Close()
	_, port, _ := net.SplitHostPort(thirdParty.Listener.Addr().String())

	sameOriginGot := make(chan string, 1)
	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "http://127.0.0.1:"+port+"/landing", http.StatusFound) // 跨源
		case "/same":
			http.Redirect(w, r, "/same-dest", http.StatusFound) // 同源
		case "/same-dest":
			sameOriginGot <- r.Header.Get("X-Api-Token")
			_, _ = io.WriteString(w, "same")
		}
	}))
	defer origin.Close()

	client := NewHTTPClient()
	defer client.Close()
	opts := OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true, CustomHeaders: map[string]string{"X-Api-Token": "secret"}}

	resp, err := client.SendRequestHttp(context.Background(), http.MethodGet, origin.URL+"/start", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	if thirdPartyGot["X-Api-Token"] != "" {
		t.Errorf("跨源重定向泄漏了自定义头 X-Api-Token=%q", thirdPartyGot["X-Api-Token"])
	}
	if thirdPartyGot["User-Agent-Present"] != "true" {
		t.Error("跨源重定向不应剥离 User-Agent")
	}
	mu.Unlock()

	resp, err = client.SendRequestHttp(context.Background(), http.MethodGet, origin.URL+"/same", "", opts)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := <-sameOriginGot; got != "secret" {
		t.Errorf("同源重定向不应剥离自定义头，得到 %q", got)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
