package sdk_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/sdk"
)

// 出站覆盖矩阵：每种出站连接分别在策略允许与拒绝两种情况下执行。拒绝时用本机监听
// 的计数断言没有任何连接或字节到达被拒绝的目标；允许时断言请求确实发出。

// wire 统计到达本机监听的连接、字节与请求路径。
type wire struct {
	conns atomic.Int64
	bytes atomic.Int64
	mu    sync.Mutex
	paths map[string]int
}

func (w *wire) hit(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.paths == nil {
		w.paths = map[string]int{}
	}
	w.paths[path]++
}

func (w *wire) path(path string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.paths[path]
}

func (w *wire) silent() bool { return w.conns.Load() == 0 && w.bytes.Load() == 0 }

type wireListener struct {
	net.Listener
	w *wire
}

func (l wireListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.w.conns.Add(1)
		conn = wireConn{Conn: conn, w: l.w}
	}
	return conn, err
}

type wireConn struct {
	net.Conn
	w *wire
}

func (c wireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.w.bytes.Add(int64(n))
	return n, err
}

func wireListen(t *testing.T) (net.Listener, *wire) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &wire{}
	t.Cleanup(func() { _ = ln.Close() })
	return wireListener{Listener: ln, w: w}, w
}

// wireHTTP 启动计数的 HTTP(S) 服务，handler 为 nil 时返回固定页面。
func wireHTTP(t *testing.T, secure bool, handler http.HandlerFunc) (string, *wire) {
	t.Helper()
	ln, w := wireListen(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.hit(r.URL.Path)
		if handler != nil {
			handler(rw, r)
			return
		}
		_, _ = io.WriteString(rw, "<html>page</html>")
	}))
	server.Listener = ln
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.URL, w
}

// wireTCPBanner 启动计数的 TCP 服务：读到数据后回送横幅。
func wireTCPBanner(t *testing.T) (string, *wire) {
	t.Helper()
	ln, w := wireListen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if n, _ := conn.Read(make([]byte, 512)); n > 0 {
					_, _ = conn.Write([]byte("SSH-2.0-test\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String(), w
}

// wireUDPEcho 启动计数的 UDP 回显服务。
func wireUDPEcho(t *testing.T) (string, *wire) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	w := &wire{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			w.conns.Add(1)
			w.bytes.Add(int64(n))
			_, _ = conn.WriteTo(append([]byte("echo:"), buf[:n]...), peer)
		}
	}()
	return conn.LocalAddr().String(), w
}

// connectProxy 是只支持 CONNECT 的 HTTP 代理。
func connectProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer upstream.Close()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { _, _ = io.Copy(upstream, reader) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

// socksProxy 是支持 CONNECT 与 UDP ASSOCIATE 的最小 SOCKS5 代理（无认证）。
func socksProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSocks(conn)
		}
	}()
	return "socks5://" + ln.Addr().String()
}

func socksAddress(reader io.Reader) (string, error) {
	head := make([]byte, 1)
	if _, err := io.ReadFull(reader, head); err != nil {
		return "", err
	}
	var host string
	switch head[0] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		size := make([]byte, 1)
		if _, err := io.ReadFull(reader, size); err != nil {
			return "", err
		}
		name := make([]byte, size[0])
		if _, err := io.ReadFull(reader, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", errors.New("unsupported address type")
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

func socksReply(conn net.Conn, addr net.Addr) {
	host, port, _ := net.SplitHostPort(addr.String())
	out := append([]byte{5, 0, 0, 1}, net.ParseIP(host).To4()...)
	number, _ := strconv.Atoi(port)
	_, _ = conn.Write(binary.BigEndian.AppendUint16(out, uint16(number)))
}

func serveSocks(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(reader, greeting); err != nil {
		return
	}
	if _, err := io.ReadFull(reader, make([]byte, greeting[1])); err != nil {
		return
	}
	_, _ = conn.Write([]byte{5, 0})
	request := make([]byte, 3)
	if _, err := io.ReadFull(reader, request); err != nil {
		return
	}
	target, err := socksAddress(reader)
	if err != nil {
		return
	}
	switch request[1] {
	case 1:
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()
		socksReply(conn, upstream.LocalAddr())
		go func() { _, _ = io.Copy(upstream, reader) }()
		_, _ = io.Copy(conn, upstream)
	case 3:
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer relay.Close()
		socksReply(conn, relay.LocalAddr())
		go func() {
			buf := make([]byte, 4096)
			for {
				n, client, err := relay.ReadFromUDP(buf)
				if err != nil || n < 4 {
					return
				}
				packet := bufio.NewReader(strings.NewReader(string(buf[3:n])))
				destination, err := socksAddress(packet)
				if err != nil {
					continue
				}
				payload, _ := io.ReadAll(packet)
				header := buf[:n-len(payload)]
				upstream, err := net.Dial("udp", destination)
				if err != nil {
					continue
				}
				_, _ = upstream.Write(payload)
				_ = upstream.SetReadDeadline(time.Now().Add(2 * time.Second))
				answer := make([]byte, 4096)
				m, err := upstream.Read(answer)
				_ = upstream.Close()
				if err == nil {
					_, _ = relay.WriteToUDP(append(append([]byte(nil), header...), answer[:m]...), client)
				}
			}
		}()
		_, _ = io.Copy(io.Discard, reader)
	}
}

// guard 是测试用的策略：deny 返回 true 的连接被拒绝，其余放行；记录每次检查。
type guard struct {
	mu   sync.Mutex
	seen []sdk.TargetRequest
	deny func(sdk.TargetRequest) bool
}

func (g *guard) policy() sdk.NetworkPolicy {
	return sdk.NetworkPolicy{CheckTarget: func(_ context.Context, request sdk.TargetRequest) error {
		g.mu.Lock()
		g.seen = append(g.seen, request)
		g.mu.Unlock()
		if g.deny != nil && g.deny(request) {
			return errors.New("blocked by test policy")
		}
		return nil
	}}
}

func (g *guard) checked(kind sdk.RequestKind) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	count := 0
	for _, request := range g.seen {
		if request.Kind == kind {
			count++
		}
	}
	return count
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil {
			t.Fatal(err)
		}
		return u.Port()
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// both 以允许与拒绝两种策略各执行一次 body。
func both(t *testing.T, body func(t *testing.T, denied bool)) {
	for _, denied := range []bool{false, true} {
		name := map[bool]string{false: "allow", true: "deny"}[denied]
		t.Run(name, func(t *testing.T) { body(t, denied) })
	}
}

func scanWithGuard(t *testing.T, rules map[string]string, target string, g *guard, opts ...sdk.Option) *sdk.TargetResult {
	t.Helper()
	e := newRuleEngine(t, rules, opts...)
	result, _ := e.ScanWith(context.Background(), target, sdk.ScanNetworkPolicy(g.policy()))
	return result
}

func TestEgressMatrix(t *testing.T) {
	page := map[string]string{"page": exprRule("page", `response.status == 200`)}

	t.Run("http", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, false, nil)
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, target) }}
			scanWithGuard(t, page, target, g)
			if denied != w.silent() || g.checked(sdk.RequestHTTP) == 0 {
				t.Fatalf("conns=%d bytes=%d checks=%d", w.conns.Load(), w.bytes.Load(), g.checked(sdk.RequestHTTP))
			}
		})
	})
	t.Run("https", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, true, nil)
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, target) }}
			scanWithGuard(t, page, target, g)
			if denied != w.silent() {
				t.Fatalf("conns=%d bytes=%d", w.conns.Load(), w.bytes.Load())
			}
		})
	})
	for _, proxy := range []string{"connect", "socks5"} {
		t.Run(proxy+"-proxy", func(t *testing.T) {
			both(t, func(t *testing.T, denied bool) {
				target, w := wireHTTP(t, false, nil)
				address := connectProxy(t)
				if proxy == "socks5" {
					address = socksProxy(t)
				}
				g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, target) }}
				result := scanWithGuard(t, page, target, g, sdk.WithProxy(address))
				if denied != w.silent() || !denied && (result == nil || len(result.Matches) != 1) {
					t.Fatalf("conns=%d bytes=%d result=%v", w.conns.Load(), w.bytes.Load(), result)
				}
			})
		})
	}
	t.Run("raw", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, false, nil)
			rule := "id: raw\ninfo:\n  name: raw\nrules:\n  r0:\n    request:\n      raw: |\n        GET /raw HTTP/1.1\n        Host: {{Hostname}}\n\n    expression: response.status == 200\nexpression: r0()\n"
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestRaw }}
			scanWithGuard(t, map[string]string{"raw": rule}, target, g)
			if denied != (w.path("/raw") == 0) || g.checked(sdk.RequestRaw) == 0 {
				t.Fatalf("raw hits=%d checks=%d", w.path("/raw"), g.checked(sdk.RequestRaw))
			}
		})
	})
	t.Run("tcp-rule", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			address, w := wireTCPBanner(t)
			rule := "id: tcp\ninfo:\n  name: tcp\nrules:\n  r0:\n    request:\n      type: tcp\n      host: " + address + "\n      data: ping\n    expression: response.raw.bcontains(b\"SSH\")\nexpression: r0()\n"
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestTCP }}
			result := scanWithGuard(t, map[string]string{"tcp": rule}, address, g)
			if denied != w.silent() || !denied && len(result.Matches) != 1 {
				t.Fatalf("conns=%d bytes=%d", w.conns.Load(), w.bytes.Load())
			}
		})
	})
	for _, via := range []string{"direct", "socks5"} {
		t.Run("udp-rule-"+via, func(t *testing.T) {
			both(t, func(t *testing.T, denied bool) {
				address, w := wireUDPEcho(t)
				rule := "id: udp\ninfo:\n  name: udp\nrules:\n  r0:\n    request:\n      type: udp\n      host: " + address + "\n      data: ping\n      read-timeout: 2\n    expression: response.raw.bcontains(b\"echo:ping\")\nexpression: r0()\n"
				g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestUDP }}
				var opts []sdk.Option
				if via == "socks5" {
					opts = append(opts, sdk.WithProxy(socksProxy(t)))
				}
				result := scanWithGuard(t, map[string]string{"udp": rule}, address, g, opts...)
				if denied != w.silent() || !denied && len(result.Matches) != 1 {
					t.Fatalf("datagrams=%d bytes=%d result=%v", w.conns.Load(), w.bytes.Load(), result)
				}
			})
		})
	}
	t.Run("icon-same-origin", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, false, func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/fav.png" {
					rw.Header().Set("Content-Type", "image/png")
					_, _ = rw.Write([]byte("\x89PNG\r\n\x1a\nicon"))
					return
				}
				rw.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(rw, `<html><link rel="icon" href="/fav.png"></html>`)
			})
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestIcon }}
			scanWithGuard(t, page, target, g)
			if denied != (w.path("/fav.png") == 0) || g.checked(sdk.RequestIcon) == 0 {
				t.Fatalf("icon hits=%d checks=%d", w.path("/fav.png"), g.checked(sdk.RequestIcon))
			}
		})
	})
	t.Run("icon-cross-origin", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			cdn, w := wireHTTP(t, false, func(rw http.ResponseWriter, _ *http.Request) {
				rw.Header().Set("Content-Type", "image/png")
				_, _ = rw.Write([]byte("\x89PNG\r\n\x1a\nicon"))
			})
			target, _ := wireHTTP(t, false, func(rw http.ResponseWriter, _ *http.Request) {
				rw.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(rw, `<html><link rel="icon" href="`+cdn+`/logo.png"></html>`)
			})
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, cdn) }}
			scanWithGuard(t, page, target, g)
			if denied != w.silent() {
				t.Fatalf("cdn conns=%d bytes=%d", w.conns.Load(), w.bytes.Load())
			}
		})
	})
	t.Run("redirect-30x-cross-host", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			other, w := wireHTTP(t, false, nil)
			entry, _ := wireHTTP(t, false, func(rw http.ResponseWriter, r *http.Request) {
				http.Redirect(rw, r, other+"/landing", http.StatusFound)
			})
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, other) }}
			scanWithGuard(t, page, entry, g)
			if denied != w.silent() {
				t.Fatalf("other conns=%d bytes=%d", w.conns.Load(), w.bytes.Load())
			}
		})
	})
	for _, kind := range []string{"refresh", "script"} {
		t.Run("redirect-"+kind, func(t *testing.T) {
			both(t, func(t *testing.T, denied bool) {
				target, w := wireHTTP(t, false, func(rw http.ResponseWriter, r *http.Request) {
					rw.Header().Set("Content-Type", "text/html")
					if r.URL.Path == "/next" {
						_, _ = io.WriteString(rw, "<html>next</html>")
						return
					}
					if kind == "refresh" {
						_, _ = io.WriteString(rw, `<html><meta http-equiv="refresh" content="0;url=/next"></html>`)
					} else {
						_, _ = io.WriteString(rw, `<html><script>window.location.href = "/next";</script></html>`)
					}
				})
				g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.URL != nil && r.URL.Path == "/next" }}
				scanWithGuard(t, page, target, g)
				redirectChecked := false
				g.mu.Lock()
				for _, request := range g.seen {
					redirectChecked = redirectChecked || request.Redirect && request.URL.Path == "/next"
				}
				g.mu.Unlock()
				if denied != (w.path("/next") == 0) || !redirectChecked {
					t.Fatalf("next hits=%d redirectChecked=%v", w.path("/next"), redirectChecked)
				}
			})
		})
	}
	t.Run("retry", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			var posts atomic.Int32
			target, _ := wireHTTP(t, false, func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" && posts.Add(1) == 1 {
					conn, _, _ := rw.(http.Hijacker).Hijack()
					_ = conn.Close()
					return
				}
				_, _ = io.WriteString(rw, "ok")
			})
			rule := "id: post\ninfo:\n  name: post\nrules:\n  r0:\n    request:\n      method: POST\n      path: /login\n      body: a=1\n    expression: response.status == 200\nexpression: r0()\n"
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.URL != nil && r.URL.Path == "/login" }}
			scanWithGuard(t, map[string]string{"post": rule}, target, g)
			checks := 0
			g.mu.Lock()
			for _, request := range g.seen {
				if request.URL != nil && request.URL.Path == "/login" {
					checks++
				}
			}
			g.mu.Unlock()
			// 允许时第一次连接被关闭，重试前再次检查目标；拒绝时只检查一次且不重试。
			if denied && (posts.Load() != 0 || checks != 1) || !denied && (posts.Load() != 2 || checks != 2) {
				t.Fatalf("posts=%d checks=%d", posts.Load(), checks)
			}
		})
	})
	t.Run("proxy-health-check", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			address, w := wireTCPBanner(t)
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Port == portOf(t, address) }}
			client := network.NewHTTPClient()
			defer client.Close()
			ctx := client.WithPolicy(context.Background(), g.policy())
			if err := network.CheckProxy(ctx, connectProxy(t), address, 2*time.Second); err != nil {
				t.Fatal(err)
			}
			// 代理在回应之前已连上目标，目标一侧的 Accept 可能稍后才返回。
			deadline := time.Now().Add(2 * time.Second)
			for !denied && w.conns.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if denied != (w.conns.Load() == 0) {
				t.Fatalf("conns=%d", w.conns.Load())
			}
		})
	})
	t.Run("resources", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, false, nil)
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestResource }}
			scanWithGuard(t, page, target, g, sdk.WithResources(sdk.ResourceOptions{Robots: true, Sitemap: true}))
			if hits := w.path("/robots.txt") + w.path("/sitemap.xml"); denied != (hits == 0) || g.checked(sdk.RequestResource) != 2 {
				t.Fatalf("resource hits=%d checks=%d", hits, g.checked(sdk.RequestResource))
			}
		})
	})
	t.Run("jarm", func(t *testing.T) {
		both(t, func(t *testing.T, denied bool) {
			target, w := wireHTTP(t, true, nil)
			g := &guard{deny: func(r sdk.TargetRequest) bool { return denied && r.Kind == sdk.RequestTLS }}
			result := scanWithGuard(t, page, target, g, sdk.WithJARM(true))
			// 页面请求复用一个连接；JARM 的 10 个探测各是一次连接。
			wantConns := int64(11)
			if denied {
				wantConns = 1
			}
			if w.conns.Load() != wantConns || result == nil || result.TLS == nil || denied != (result.TLS.JARM == "") {
				t.Fatalf("conns=%d result=%+v", w.conns.Load(), result)
			}
		})
	})
}

// Dial 替代直连拨号：HTTP、TCP、UDP、JARM 与经代理的连接都由它建立。
func TestEgressUsesPolicyDial(t *testing.T) {
	target, _ := wireHTTP(t, true, nil)
	tcpAddress, _ := wireTCPBanner(t)
	var mu sync.Mutex
	dialed := map[string]int{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed[network+" "+address]++
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	tcpRule := "id: tcp\ninfo:\n  name: tcp\nrules:\n  r0:\n    request:\n      type: tcp\n      host: " + tcpAddress + "\n      data: ping\n    expression: response.raw.bcontains(b\"SSH\")\nexpression: r0()\n"
	e := newRuleEngine(t, map[string]string{"page": exprRule("page", `response.status == 200`), "tcp": tcpRule}, sdk.WithJARM(true), sdk.WithNetworkPolicy(sdk.NetworkPolicy{Dial: dial}))
	result, err := e.Scan(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(target, "https://")
	snapshot := func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		copied := make(map[string]int, len(dialed))
		for key, value := range dialed {
			copied[key] = value
		}
		clear(dialed)
		return copied
	}
	if got := snapshot(); len(result.Matches) != 2 || got["tcp "+host] != 11 || got["tcp "+tcpAddress] != 1 {
		t.Fatalf("matches=%v dialed=%v", resultIDs(result), got)
	}
	// 经代理时 Dial 只用于连接代理服务器本身。
	proxy := connectProxy(t)
	proxied := newRuleEngine(t, map[string]string{"page": exprRule("page", `response.status == 200`)}, sdk.WithProxy(proxy), sdk.WithNetworkPolicy(sdk.NetworkPolicy{Dial: dial}))
	if _, err := proxied.Scan(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(); got["tcp "+strings.TrimPrefix(proxy, "http://")] == 0 || got["tcp "+host] != 0 {
		t.Fatalf("dialed=%v", got)
	}
}
