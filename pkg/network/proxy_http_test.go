package network

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type connectProxyOpts struct {
	status   string // 自定义 CONNECT 响应状态行，如 "403 Forbidden"；空表示 200 并建立隧道
	wantUser string
	wantPass string
	hang     bool // 读到 CONNECT 后不回应，用于验证超时/取消
}

// startConnectProxy 启动一个可配置的 HTTP CONNECT 代理，返回代理地址与被使用计数。
func startConnectProxy(t *testing.T, opts connectProxyOpts) (string, *int32Counter) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	used := &int32Counter{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				used.add(1)
				if opts.wantUser != "" {
					user, pass, ok := decodeProxyBasicAuth(req.Header.Get("Proxy-Authorization"))
					if !ok || user != opts.wantUser || pass != opts.wantPass {
						_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
						return
					}
				}
				if opts.hang {
					select {} // 不回应，直到连接被对端关闭
				}
				if opts.status != "" {
					_, _ = c.Write([]byte("HTTP/1.1 " + opts.status + "\r\n\r\n"))
					return
				}
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer upstream.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go func() { _, _ = io.Copy(upstream, br) }()
				_, _ = io.Copy(c, upstream)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), used
}

func decodeProxyBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

func TestHTTPConnectRejectsNon200(t *testing.T) {
	target := tcpEchoServer(t)
	proxy, used := startConnectProxy(t, connectProxyOpts{status: "403 Forbidden"})
	_, err := dialAndEcho(t, "tcp", target, proxy, "ping")
	if err == nil {
		t.Fatal("代理拒绝 CONNECT 时应返回错误，而非已关闭的连接")
	}
	if !strings.Contains(err.Error(), "CONNECT") {
		t.Fatalf("错误信息应指明 CONNECT 被拒绝: %v", err)
	}
	if used.load() == 0 {
		t.Fatal("代理未被访问")
	}
}

func TestHTTPConnectBasicAuth(t *testing.T) {
	target := tcpEchoServer(t)
	proxy, _ := startConnectProxy(t, connectProxyOpts{wantUser: "scanuser", wantPass: "scanpass"})
	host := strings.TrimPrefix(proxy, "http://")

	got, err := dialAndEcho(t, "tcp", target, "http://scanuser:scanpass@"+host, "ping")
	if err != nil || got != "ping" {
		t.Fatalf("正确凭据应建连: got=%q err=%v", got, err)
	}
	if _, err := dialAndEcho(t, "tcp", target, "http://scanuser:wrong@"+host, "ping"); err == nil {
		t.Fatal("错误凭据应握手失败")
	}
	if _, err := dialAndEcho(t, "tcp", target, proxy, "ping"); err == nil {
		t.Fatal("缺少凭据应握手失败")
	}
}

func TestHTTPConnectHonorsTimeout(t *testing.T) {
	target := tcpEchoServer(t)
	proxy, _ := startConnectProxy(t, connectProxyOpts{hang: true})
	start := time.Now()
	_, err := dialAndEcho(t, "tcp", target, proxy, "ping")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("代理不回应时应超时失败，而非永久阻塞")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("超时未被遵守，耗时 %v", elapsed)
	}
}
