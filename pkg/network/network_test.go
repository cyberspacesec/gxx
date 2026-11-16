package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRawHTTPResponseAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Length", "4")
		if r.Method != http.MethodHead {
			fmt.Fprint(w, "pong")
		}
	}))
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	opts := OptionsRequest{Timeout: time.Second, InsecureSkipVerify: true}
	for _, method := range []string{"GET", "HEAD"} {
		resp, err := client.SendRawRequest(context.Background(), method+" / HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, opts)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || method == "GET" && string(data) != "pong" || method == "HEAD" && len(data) != 0 {
			t.Fatalf("%s: status=%d body=%q err=%v", method, resp.StatusCode, data, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.SendRawRequest(ctx, "GET /wait HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, opts)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("取消未中断 Raw HTTP: %v", err)
	}
}

func TestRawHTTPBufferedBodyCannotSucceedAfterCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4")
		fmt.Fprint(w, "pong")
		w.(http.Flusher).Flush()
	}))
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := client.SendRawRequest(ctx, "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, OptionsRequest{Timeout: time.Second, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	if body, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后缓冲正文仍被视为成功: body=%q err=%v", body, err)
	}
}

func TestTCPAndUDPResponses(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			var address string
			if protocol == "tcp" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				address = listener.Addr().String()
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					buffer := make([]byte, 16)
					if _, err := conn.Read(buffer); err == nil {
						conn.Write([]byte("pong"))
					}
				}()
			} else {
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				address = conn.LocalAddr().String()
				go func() {
					buffer := make([]byte, 16)
					_, peer, err := conn.ReadFrom(buffer)
					if err == nil {
						conn.WriteTo([]byte("pong"), peer)
					}
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, err := NewClientContext(ctx, address, TcpOrUdpConfig{Network: protocol, MaxRetries: 1, ReadTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Send([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			got, err := client.Receive()
			if err != nil || string(got) != "pong" {
				t.Fatalf("响应=%q err=%v", got, err)
			}
		})
	}
}

// TestParseEndpoint 锁定连接地址的唯一解析入口：主机、端口与是否握手由同一处决定。
//
// 回归点：曾有两个解析器分别推断主机、端口和 TLS。对 "2001:db8::1:80" 这类
// 无括号多冒号地址，一侧读成 IPv6 加端口、另一侧读成完整 IPv6，同一条规则连向
// 不同主机；带 tcp://、ssl:// 的无括号 IPv6 还会随 Go 版本改变结论。
func TestParseEndpoint(t *testing.T) {
	for _, tc := range []struct {
		address string
		network string
		host    string
		port    string
		tls     bool
		wantErr bool
	}{
		// 不带协议：443 与未写端口视为 TLS，其余端口明文。
		{address: "example.com", host: "example.com", port: "443", tls: true},
		{address: "example.com:443", host: "example.com", port: "443", tls: true},
		{address: "example.com:22", host: "example.com", port: "22"},
		{address: "example.com:8443", host: "example.com", port: "8443"},
		{address: " 127.0.0.1:2222 ", host: "127.0.0.1", port: "2222"},
		// 协议决定是否握手与缺省端口；路径、查询与用户信息被忽略。
		{address: "https://example.com", host: "example.com", port: "443", tls: true},
		{address: "https://example.com:8443/login?next=/", host: "example.com", port: "8443", tls: true},
		{address: "ssl://example.com:8443", host: "example.com", port: "8443", tls: true},
		{address: "tls://example.com", host: "example.com", port: "443", tls: true},
		{address: "http://example.com", host: "example.com", port: "80"},
		{address: "http://example.com:443/path", host: "example.com", port: "443"},
		{address: "tcp://example.com:22", host: "example.com", port: "22"},
		{address: "tcp://example.com", host: "example.com", port: "80"},
		{address: "HTTPS://user:pass@example.com/a@b", host: "example.com", port: "443", tls: true},
		// 方括号界定主机：IPv6 必须加，域名与 IPv4 也可以加。
		{address: "[::1]", host: "::1", port: "443", tls: true},
		{address: "[::1]:8080", host: "::1", port: "8080"},
		{address: "[2001:db8::1]:80", host: "2001:db8::1", port: "80"},
		{address: "https://[::1]:8443", host: "::1", port: "8443", tls: true},
		{address: "https://user@[::1]:443", host: "::1", port: "443", tls: true},
		{address: "tcp://[2001:db8::1]:80", host: "2001:db8::1", port: "80"},
		{address: "[fe80::1%eth0]:80", host: "fe80::1%eth0", port: "80"},
		{address: "[fe80::1%25eth0]:80", host: "fe80::1%eth0", port: "80"},
		{address: "[::ffff:192.0.2.1]:22", host: "::ffff:192.0.2.1", port: "22"},
		{address: "[example.com]:22", host: "example.com", port: "22"},
		{address: "[192.0.2.1]:22", host: "192.0.2.1", port: "22"},
		// UDP 没有 TLS 通道：端口按地址取值，但从不握手。
		{address: "127.0.0.1:443", network: "udp", host: "127.0.0.1", port: "443"},
		{address: "https://example.com", network: "udp", host: "example.com", port: "443"},
		{address: "example.com", network: "udp", host: "example.com", port: "80"},
		{address: "udp://example.com:53", network: "udp", host: "example.com", port: "53"},
		// 歧义或畸形输入一律拒绝，不猜测读法。
		{address: "   ", wantErr: true},
		{address: "::1", wantErr: true},
		{address: "2001:db8::443", wantErr: true},
		{address: "2001:db8::1:80", wantErr: true},
		{address: "tcp://2001:db8::1:80", wantErr: true},
		{address: "ssl://fe80::1:8443", wantErr: true},
		{address: "https://2001:db8::1:443", wantErr: true},
		{address: "example.com:8080:22", wantErr: true},
		{address: "example.com/admin", wantErr: true},
		{address: "example.com?q=1", wantErr: true},
		{address: "user@example.com:22", wantErr: true},
		{address: "example.com:0", wantErr: true},
		{address: "example.com:", wantErr: true},
		{address: "example.com:65536", wantErr: true},
		{address: "example.com:+80", wantErr: true},
		{address: "exa mple.com:80", wantErr: true},
		{address: "https://", wantErr: true},
		{address: "[::1", wantErr: true},
		{address: "[::1]8080", wantErr: true},
		{address: "[::1]:", wantErr: true},
		{address: "[not:ipv6]:80", wantErr: true},
		{address: "[fe80::1%]:80", wantErr: true},
		{address: "[]:80", wantErr: true},
		{address: "ftp://example.com", wantErr: true},
		{address: "example.com:80", network: "sctp", wantErr: true},
	} {
		t.Run(tc.address+"/"+tc.network, func(t *testing.T) {
			endpoint, err := ParseEndpoint(tc.address, tc.network)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错，实际返回 %+v", endpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if endpoint.Host != tc.host || endpoint.Port != tc.port || endpoint.TLS != tc.tls {
				t.Fatalf("得到 %+v，期望 host=%q port=%q tls=%v", endpoint, tc.host, tc.port, tc.tls)
			}
			if want := net.JoinHostPort(tc.host, tc.port); endpoint.Address() != want {
				t.Fatalf("拨号地址 %q，期望 %q", endpoint.Address(), want)
			}
		})
	}
}

// TestUDPNeverPerformsTLSHandshake 确认 UDP 不会进入 TLS 握手分支。
func TestUDPNeverPerformsTLSHandshake(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buffer := make([]byte, 16)
		if _, peer, err := conn.ReadFrom(buffer); err == nil {
			conn.WriteTo([]byte("pong"), peer)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// 写成 tls:// 的 UDP 地址必须照常收发，而不是卡在握手上。
	client, err := NewClientContext(ctx, "tls://"+conn.LocalAddr().String(), TcpOrUdpConfig{Network: "udp", MaxRetries: 1, ReadTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.endpoint.TLS {
		t.Fatal("UDP 端点不应启用 TLS")
	}
	if err := client.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got, err := client.Receive(); err != nil || string(got) != "pong" {
		t.Fatalf("响应=%q err=%v", got, err)
	}
}

// segmentedServer 在收到请求后按给定延迟分段写出响应，然后保持连接不关闭。
func segmentedServer(t *testing.T, first time.Duration, gap time.Duration, parts ...string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 16)
				if _, err := conn.Read(buffer); err != nil {
					return
				}
				time.Sleep(first)
				for index, part := range parts {
					if index > 0 {
						time.Sleep(gap)
					}
					if _, err := conn.Write([]byte(part)); err != nil {
						return
					}
				}
				<-done
			}()
		}
	}()
	return listener.Addr().String()
}

// TestReceiveCollectsSegmentedResponse 锁定分段响应的接收：对端不关闭连接时，
// 接收在空闲时间内等待后续分段，而不是在首段之后立即返回或被固定窗口截断。
//
// 回归点：空闲窗口曾固定为 100ms，间隔 150ms 的两段 banner 只读到第一段，
// 依赖第二段的规则漏报；而总超时还剩数秒。
func TestReceiveCollectsSegmentedResponse(t *testing.T) {
	receive := func(t *testing.T, address string, conf TcpOrUdpConfig) (string, time.Duration) {
		t.Helper()
		conf.Network, conf.MaxRetries = "tcp", 1
		client, err := NewClientContext(context.Background(), address, conf)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.Send([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		got, err := client.Receive()
		if err != nil {
			t.Fatal(err)
		}
		return string(got), time.Since(start)
	}

	t.Run("配置的空闲时间覆盖分段间隔", func(t *testing.T) {
		address := segmentedServer(t, 0, 150*time.Millisecond, "220 ready\r\n", "220 banner\r\n")
		got, elapsed := receive(t, address, TcpOrUdpConfig{ReadTimeout: 3 * time.Second, ReadIdle: 500 * time.Millisecond})
		if got != "220 ready\r\n220 banner\r\n" {
			t.Fatalf("分段响应被截断: %q", got)
		}
		// 两段读完后只再等待一个空闲时间，不会耗尽总超时。
		if elapsed > 2*time.Second {
			t.Fatalf("接收耗时 %v，空闲结束后未及时返回", elapsed)
		}
	})

	t.Run("首段越慢自适应等待越久", func(t *testing.T) {
		// 首段 200ms 后到达，自适应空闲时间为 400ms，足以等到 250ms 之后的第二段。
		address := segmentedServer(t, 200*time.Millisecond, 250*time.Millisecond, "part1", "part2")
		got, _ := receive(t, address, TcpOrUdpConfig{ReadTimeout: 3 * time.Second})
		if got != "part1part2" {
			t.Fatalf("自适应空闲时间未覆盖分段间隔: %q", got)
		}
	})

	t.Run("单段响应在最短空闲时间后返回", func(t *testing.T) {
		address := segmentedServer(t, 0, 0, "SSH-2.0-test\r\n")
		got, elapsed := receive(t, address, TcpOrUdpConfig{ReadTimeout: 3 * time.Second})
		if got != "SSH-2.0-test\r\n" {
			t.Fatalf("响应=%q", got)
		}
		if elapsed > time.Second {
			t.Fatalf("单段响应耗时 %v，应在最短空闲时间后返回", elapsed)
		}
	})
}

// TestReceiveHonorsReadTimeout 锁定 Receive 的总时长受 ReadTimeout 约束。
//
// 回归点：为合并多包响应引入空闲窗口时，每轮循环都重置截止时间，使慢速
// 滴流的服务端可以把单次 Receive 拖到远超 ReadTimeout（实测 1s 配置下耗时
// 5.5s），只有 context 取消能兜底；用 context.Background() 的调用方则无界。
func TestReceiveHonorsReadTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 16)
		if _, err := conn.Read(buffer); err != nil {
			return
		}
		// 每 90ms 滴一个字节：持续慢于空闲窗口，但永不结束。
		for i := 0; i < 200; i++ {
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(90 * time.Millisecond)
		}
	}()

	readTimeout := time.Second
	client, err := NewClientContext(context.Background(), listener.Addr().String(),
		TcpOrUdpConfig{Network: "tcp", MaxRetries: 1, ReadTimeout: readTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	got, err := client.Receive()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("未读到任何数据")
	}
	// 留一倍余量吸收调度抖动；回归时此处是 5s 以上。
	if elapsed > 2*readTimeout {
		t.Fatalf("Receive 耗时 %v 超出 ReadTimeout %v 的约束", elapsed, readTimeout)
	}
}
