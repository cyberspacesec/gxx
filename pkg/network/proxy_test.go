package network

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─────────────────────── 测试用代理与回显服务 ───────────────────────

// tcpEchoServer 回显首个读到的数据，用于验证 TCP 连通性。
func tcpEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// udpEchoServer 回显 UDP 数据报。
func udpEchoServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(append([]byte("echo:"), buf[:n]...), peer)
		}
	}()
	return conn.LocalAddr().String()
}

// httpConnectProxy 启动仅支持 CONNECT 的 HTTP 代理，记录是否被使用。
func httpConnectProxy(t *testing.T) (string, *int32Counter) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	counter := &int32Counter{}
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
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				counter.add(1)
				_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), counter
}

type int32Counter struct {
	mu sync.Mutex
	n  int
}

func (c *int32Counter) add(n int) {
	c.mu.Lock()
	c.n += n
	c.mu.Unlock()
}
func (c *int32Counter) load() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// socks5TestProxy 是支持 CONNECT 与 UDP ASSOCIATE 的最小 SOCKS5 服务，可选用户名/密码认证。
type socks5TestProxy struct {
	addr          string
	wantUser      string
	wantPass      string
	tcpAssociates *int32Counter
	udpAssociates *int32Counter
}

func startSOCKS5Proxy(t *testing.T, user, pass string) *socks5TestProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &socks5TestProxy{addr: ln.Addr().String(), wantUser: user, wantPass: pass, tcpAssociates: &int32Counter{}, udpAssociates: &int32Counter{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(t, c)
		}
	}()
	return p
}

func (p *socks5TestProxy) serve(t *testing.T, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	// 方法协商
	ver, _ := reader.ReadByte()
	if ver != socks5Version {
		return
	}
	nmethods, _ := reader.ReadByte()
	methods := make([]byte, nmethods)
	_, _ = io.ReadFull(reader, methods)
	if p.wantUser != "" {
		if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPw}); err != nil {
			return
		}
		if !p.checkAuth(reader, conn) {
			return
		}
	} else {
		if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
			return
		}
	}
	// 请求
	head := make([]byte, 4)
	if _, err := io.ReadFull(reader, head); err != nil {
		return
	}
	host, _ := readSOCKS5Host(reader, head[3])
	portBytes := make([]byte, 2)
	_, _ = io.ReadFull(reader, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	switch head[1] {
	case 0x01: // CONNECT
		p.tcpAssociates.add(1)
		p.handleConnect(conn, reader, net.JoinHostPort(host, strconv.Itoa(int(port))))
	case socks5CmdUDP:
		p.udpAssociates.add(1)
		p.handleUDP(conn)
	}
}

func (p *socks5TestProxy) checkAuth(reader *bufio.Reader, conn net.Conn) bool {
	if v, _ := reader.ReadByte(); v != 0x01 {
		return false
	}
	ulen, _ := reader.ReadByte()
	user := make([]byte, ulen)
	_, _ = io.ReadFull(reader, user)
	plen, _ := reader.ReadByte()
	pass := make([]byte, plen)
	_, _ = io.ReadFull(reader, pass)
	if string(user) == p.wantUser && string(pass) == p.wantPass {
		_, _ = conn.Write([]byte{0x01, 0x00})
		return true
	}
	_, _ = conn.Write([]byte{0x01, 0x01})
	return false
}

func (p *socks5TestProxy) reply(conn net.Conn, status byte, bnd net.Addr) {
	out := []byte{socks5Version, status, 0x00}
	host, portStr, _ := net.SplitHostPort(bnd.String())
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		out = append(out, socks5AtypIPv4)
		out = append(out, v4...)
	} else {
		out = append(out, socks5AtypIPv6)
		out = append(out, ip.To16()...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	out = append(out, portBytes...)
	_, _ = conn.Write(out)
}

func (p *socks5TestProxy) handleConnect(conn net.Conn, reader *bufio.Reader, target string) {
	up, err := net.Dial("tcp", target)
	if err != nil {
		p.reply(conn, 0x01, &net.TCPAddr{IP: net.IPv4zero})
		return
	}
	defer up.Close()
	p.reply(conn, 0x00, up.LocalAddr())
	go func() { _, _ = io.Copy(up, reader) }()
	_, _ = io.Copy(conn, up)
}

// handleUDP 建立 UDP 中继：接收客户端数据报（含 SOCKS5 UDP 头），转发到目标并回送响应。
func (p *socks5TestProxy) handleUDP(conn net.Conn) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		p.reply(conn, 0x01, &net.UDPAddr{IP: net.IPv4zero})
		return
	}
	defer relay.Close()
	p.reply(conn, 0x00, relay.LocalAddr())
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		var clientAddr *net.UDPAddr
		for {
			n, peer, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientAddr = peer
			payload, perr := stripSOCKS5UDPHeader(buf[:n])
			if perr != nil {
				continue
			}
			// 从头部解析目标地址
			target, herr := parseUDPTarget(buf[:n])
			if herr != nil {
				continue
			}
			upstream, err := net.Dial("udp", target)
			if err != nil {
				continue
			}
			_, _ = upstream.Write(payload)
			_ = upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp := make([]byte, 4096)
			rn, rerr := upstream.Read(resp)
			upstream.Close()
			if rerr != nil {
				continue
			}
			header := buf[:n-len(payload)] // 复用请求头（目标地址相同）
			out := append(append([]byte{}, header...), resp[:rn]...)
			_, _ = relay.WriteToUDP(out, clientAddr)
		}
	}()
	// 控制连接关闭即结束中继
	_, _ = io.Copy(io.Discard, conn)
	_ = relay.Close()
	<-done
}

// parseUDPTarget 从 SOCKS5 UDP 数据报头解析目标 host:port。
func parseUDPTarget(packet []byte) (string, error) {
	if len(packet) < 4 {
		return "", errors.New("短包")
	}
	offset := 4
	var host string
	switch packet[3] {
	case socks5AtypIPv4:
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case socks5AtypIPv6:
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	case socks5AtypDomain:
		l := int(packet[offset])
		offset++
		host = string(packet[offset : offset+l])
		offset += l
	}
	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// ─────────────────────────── 测试 ───────────────────────────

func TestNormalizeProxyURL(t *testing.T) {
	cases := []struct {
		raw        string
		wantErr    bool
		wantScheme string
	}{
		{"", false, ""},
		{"http://127.0.0.1:8080", false, "http"},
		{"https://127.0.0.1:8080", false, "https"},
		{"socks5://127.0.0.1:1080", false, "socks5"},
		{"socks5h://127.0.0.1:1080", false, "socks5"},
		{"SOCKS5H://127.0.0.1:1080", false, "socks5"},
		{"socks4://127.0.0.1:1080", false, "socks4"},
		{"socks5://user:pass@127.0.0.1:1080", false, "socks5"},
		{"ftp://127.0.0.1:21", true, ""},
		{"http://", true, ""},
	}
	for _, tc := range cases {
		u, err := normalizeProxyURL(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: 期望错误，得到 nil", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: 未期望的错误 %v", tc.raw, err)
			continue
		}
		if tc.raw == "" {
			if u != nil {
				t.Errorf("空代理应返回 nil")
			}
			continue
		}
		if strings.ToLower(u.Scheme) != tc.wantScheme {
			t.Errorf("%q: scheme=%q 期望 %q", tc.raw, u.Scheme, tc.wantScheme)
		}
	}
}

func dialAndEcho(t *testing.T, network, target, proxy, payload string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialContext(ctx, network, target, proxy, 3*time.Second, false, "", true)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func TestDialTCPDirectAndProxies(t *testing.T) {
	target := tcpEchoServer(t)
	httpProxy, httpUsed := httpConnectProxy(t)
	socks := startSOCKS5Proxy(t, "", "")
	authSocks := startSOCKS5Proxy(t, "scanuser", "scanpass")

	cases := []struct {
		name, proxy string
	}{
		{"直连", ""},
		{"HTTP 代理", httpProxy},
		{"SOCKS5 代理", "socks5://" + socks.addr},
		{"SOCKS5h 代理", "socks5h://" + socks.addr},
		{"SOCKS5 认证代理", "socks5://scanuser:scanpass@" + authSocks.addr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dialAndEcho(t, "tcp", target, tc.proxy, "ping")
			if err != nil || got != "ping" {
				t.Fatalf("回显=%q err=%v", got, err)
			}
		})
	}
	if httpUsed.load() == 0 {
		t.Error("HTTP 代理未被使用")
	}
	if socks.tcpAssociates.load() == 0 {
		t.Error("SOCKS5 代理未被使用")
	}
}

func TestDialUDPDirectAndSOCKS5(t *testing.T) {
	target := udpEchoServer(t)
	socks := startSOCKS5Proxy(t, "", "")
	authSocks := startSOCKS5Proxy(t, "u", "p")

	cases := []struct {
		name, proxy string
	}{
		{"UDP 直连", ""},
		{"UDP over SOCKS5", "socks5://" + socks.addr},
		{"UDP over SOCKS5h", "socks5h://" + socks.addr},
		{"UDP over SOCKS5 认证", "socks5://u:p@" + authSocks.addr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dialAndEcho(t, "udp", target, tc.proxy, "hello")
			if err != nil || got != "echo:hello" {
				t.Fatalf("回显=%q err=%v", got, err)
			}
		})
	}
	if socks.udpAssociates.load() == 0 {
		t.Error("SOCKS5 UDP ASSOCIATE 未被使用")
	}
}

func TestDialUDPOverHTTPProxyRejected(t *testing.T) {
	target := udpEchoServer(t)
	httpProxy, _ := httpConnectProxy(t)
	_, err := dialAndEcho(t, "udp", target, httpProxy, "x")
	if err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("HTTP 代理 + UDP 应明确报错，得到 err=%v", err)
	}
}

func TestClientContextTCPUDPThroughSOCKS5(t *testing.T) {
	socks := startSOCKS5Proxy(t, "", "")
	for _, protocol := range []string{"tcp", "udp"} {
		var target string
		if protocol == "tcp" {
			target = tcpEchoServer(t)
		} else {
			target = udpEchoServer(t)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		client, err := NewClientContext(ctx, target, TcpOrUdpConfig{Network: protocol, MaxRetries: 1, ReadTimeout: 2 * time.Second, DialTimeout: 3 * time.Second, ProxyURL: "socks5h://" + socks.addr})
		if err != nil {
			cancel()
			t.Fatalf("%s 经 SOCKS5 建连失败: %v", protocol, err)
		}
		if err := client.Send([]byte("data")); err != nil {
			client.Close()
			cancel()
			t.Fatalf("%s Send 失败: %v", protocol, err)
		}
		got, err := client.Receive()
		client.Close()
		cancel()
		want := "data"
		if protocol == "udp" {
			want = "echo:data"
		}
		if err != nil || string(got) != want {
			t.Fatalf("%s 经 SOCKS5：响应=%q 期望=%q err=%v", protocol, got, want, err)
		}
	}
	if socks.tcpAssociates.load() == 0 || socks.udpAssociates.load() == 0 {
		t.Fatalf("SOCKS5 代理未同时用于 TCP 和 UDP: tcp=%d udp=%d", socks.tcpAssociates.load(), socks.udpAssociates.load())
	}
}

func TestProxyErrorMessagesAreClear(t *testing.T) {
	_, err := DialContext(context.Background(), "tcp", "127.0.0.1:9", "ftp://127.0.0.1:21", time.Second, false, "", true)
	if err == nil || !strings.Contains(err.Error(), "不支持的代理协议") {
		t.Fatalf("非法代理协议应明确报错: %v", err)
	}
	_, err = DialContext(context.Background(), "udp", "127.0.0.1:53", fmt.Sprintf("socks4://127.0.0.1:1080"), time.Second, false, "", true)
	if err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("SOCKS4 + UDP 应明确报错: %v", err)
	}
}
