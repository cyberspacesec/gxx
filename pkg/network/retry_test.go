package network

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 第一次连接被对方直接关闭时，非 GET 规则请求重试一次并重放请求体。
func TestRuleRequestRetriesOnceAndReplaysBody(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if attempts.Add(1) == 1 {
			hijacker := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			_ = conn.Close()
			return
		}
		_, _ = w.Write(body)
	}))
	server.Start()
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	resp, err := client.SendRequestHttp(context.Background(), http.MethodPost, server.URL+"/login", "user=a", OptionsRequest{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "user=a" || attempts.Load() != 2 {
		t.Fatalf("body=%q attempts=%d", body, attempts.Load())
	}
}

// 请求地址按原样发出：查询参数的顺序与写法不被改写。
func TestQueryStringIsSentVerbatim(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.RequestURI
	}))
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	resp, err := client.SendRequestHttp(context.Background(), http.MethodGet, server.URL+"/index.php?m=Admin&c=Index&a=", "", OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := <-seen; got != "/index.php?m=Admin&c=Index&a=" {
		t.Fatalf("请求地址被改写: %q", got)
	}
}

// 宽松解析：合法报文按 HTTP 解析并解开压缩正文；畸形报文保留响应头，其余作为正文。
func TestParseTolerantResponse(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte("hello"))
	_ = gz.Close()
	raw := append([]byte("HTTP/1.1 201 Created\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n"), compressed.Bytes()...)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := parseTolerantResponse(raw, req)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || string(body) != "hello" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("status=%d body=%q header=%v", resp.StatusCode, body, resp.Header)
	}

	resp = parseTolerantResponse([]byte("ICY 200 OK\r\nicy-name: radio\r\n\r\nstream"), req)
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "stream" || resp.Header.Get("Icy-Name") != "radio" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("status=%d body=%q header=%v", resp.StatusCode, body, resp.Header)
	}

	resp = parseTolerantResponse([]byte("SSH-2.0-OpenSSH_9.6\r\n"), req)
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

// 证书不受信任、协议不支持与重定向超限不重试；连接被拒绝之类的传输错误重试。
func TestRetryableError(t *testing.T) {
	cases := map[string]bool{
		`Get "http://a/": stopped after 10 redirects`:         false,
		`Post "ftp://a/": unsupported protocol scheme "ftp"`:  false,
		"dial tcp 127.0.0.1:1: connect: connection refused":   true,
		"read tcp 127.0.0.1:1->127.0.0.1:2: connection reset": true,
	}
	for message, want := range cases {
		if got := retryableError(&net.OpError{Op: "dial", Err: errString(message)}); got != want {
			t.Errorf("%q: got %v want %v", message, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
