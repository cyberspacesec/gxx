package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingListener 统计到达本机监听的连接与字节，用于断言被拒绝的目标没有收到任何数据。
type countingListener struct {
	net.Listener
	conns atomic.Int32
	bytes atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.conns.Add(1)
		conn = &countingConn{Conn: conn, owner: l}
	}
	return conn, err
}

type countingConn struct {
	net.Conn
	owner *countingListener
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.owner.bytes.Add(int64(n))
	return n, err
}

func countedServer(t *testing.T, handler http.Handler) (*httptest.Server, *countingListener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: ln}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = counted
	server.Start()
	t.Cleanup(server.Close)
	return server, counted
}

func denyPort(port string) Policy {
	return Policy{CheckTarget: func(_ context.Context, request TargetRequest) error {
		if request.Port == port {
			return errors.New("blocked")
		}
		return nil
	}}
}

func TestCheckTargetDeniesBeforeAnyByte(t *testing.T) {
	server, counted := countedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	u, _ := url.Parse(server.URL)
	client := NewHTTPClient()
	defer client.Close()
	client.SetPolicy(denyPort(u.Port()))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		_, err := client.SendRequestHttp(context.Background(), method, server.URL+"/", "a=1", OptionsRequest{Timeout: 2 * time.Second})
		var denied *DeniedError
		if !errors.As(err, &denied) || denied.Request.Kind != RequestHTTP || denied.Request.Host != "127.0.0.1" {
			t.Fatalf("%s 应被策略拒绝: %v", method, err)
		}
	}
	if _, err := client.SendRawRequest(context.Background(), "GET / HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n", server.URL, OptionsRequest{Timeout: 2 * time.Second}); err == nil {
		t.Fatal("Raw 请求应被策略拒绝")
	}
	if counted.conns.Load() != 0 || counted.bytes.Load() != 0 {
		t.Fatalf("被拒绝的目标收到了连接=%d 字节=%d", counted.conns.Load(), counted.bytes.Load())
	}
}

// 30x 指向的下一跳被拒绝时，请求整体失败，下一跳的监听不会收到任何数据。
func TestCheckTargetCoversRedirectHops(t *testing.T) {
	foreign, counted := countedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/landing", http.StatusFound)
	}))
	defer origin.Close()
	u, _ := url.Parse(foreign.URL)
	client := NewHTTPClient()
	defer client.Close()
	var redirectSeen atomic.Bool
	client.SetPolicy(Policy{CheckTarget: func(_ context.Context, request TargetRequest) error {
		if request.Port == u.Port() {
			redirectSeen.Store(request.Redirect)
			return errors.New("blocked")
		}
		return nil
	}})
	if _, err := client.SendRequestHttp(context.Background(), http.MethodGet, origin.URL+"/", "", OptionsRequest{Timeout: 2 * time.Second, FollowRedirects: true}); err == nil {
		t.Fatal("下一跳被拒绝时请求应失败")
	}
	if !redirectSeen.Load() || counted.conns.Load() != 0 {
		t.Fatalf("redirect=%v conns=%d", redirectSeen.Load(), counted.conns.Load())
	}
}

// Redirect 返回 RedirectStop 时返回 30x 响应本身，不访问下一跳。
func TestRedirectStopReturnsRedirectResponse(t *testing.T) {
	foreign, counted := countedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/landing", http.StatusFound)
	}))
	defer origin.Close()
	client := NewHTTPClient()
	defer client.Close()
	ctx := client.WithPolicy(context.Background(), Policy{Redirect: func(context.Context, *url.URL, *url.URL) RedirectAction { return RedirectStop }})
	resp, err := client.SendRequestHttp(ctx, http.MethodGet, origin.URL+"/", "", OptionsRequest{Timeout: 2 * time.Second, FollowRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || counted.conns.Load() != 0 {
		t.Fatalf("status=%d conns=%d", resp.StatusCode, counted.conns.Load())
	}
}

// 请求级 Dial 拨出的连接只属于发起它的请求，不进入连接池；客户端级拨号的连接照常复用。
func TestScopedDialIsNotPooled(t *testing.T) {
	server, counted := countedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	client := NewHTTPClient()
	defer client.Close()
	var mu sync.Mutex
	dials := map[string]int{}
	scoped := func(name string) context.Context {
		return client.WithPolicy(context.Background(), Policy{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			dials[name]++
			mu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}})
	}
	get := func(ctx context.Context) {
		t.Helper()
		resp, err := client.SendRequestHttp(ctx, http.MethodGet, server.URL+"/", "", OptionsRequest{Timeout: 2 * time.Second, FollowRedirects: true})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	get(context.Background())
	get(context.Background())
	if counted.conns.Load() != 1 {
		t.Fatalf("客户端级请求应复用连接: %d", counted.conns.Load())
	}
	a, b := scoped("a"), scoped("b")
	get(a)
	get(b)
	get(a)
	mu.Lock()
	defer mu.Unlock()
	if dials["a"] != 2 || dials["b"] != 1 || counted.conns.Load() != 4 {
		t.Fatalf("请求级拨号被复用: dials=%v conns=%d", dials, counted.conns.Load())
	}
}

// 逐字段覆盖：请求级未设置的字段沿用客户端级策略。
func TestPolicyOverrideIsFieldWise(t *testing.T) {
	client := NewHTTPClient()
	defer client.Close()
	engine := Policy{CheckTarget: func(context.Context, TargetRequest) error { return errors.New("engine") }}
	client.SetPolicy(engine)
	ctx := client.WithPolicy(context.Background(), Policy{Redirect: func(context.Context, *url.URL, *url.URL) RedirectAction { return RedirectStop }})
	policy := PolicyFrom(ctx)
	if policy.CheckTarget == nil || policy.Redirect == nil || policy.CheckTarget(ctx, TargetRequest{}).Error() != "engine" {
		t.Fatal("覆盖应只替换非 nil 字段")
	}
}

// TCP/UDP 连接与代理健康探测经过 ctx 中的策略：拨号使用策略的 Dial，被拒绝的目标收不到连接。
func TestDialContextAndCheckProxyUsePolicy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counted := &countingListener{Listener: ln}
	defer counted.Close()
	go func() {
		for {
			conn, err := counted.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, conn); _ = conn.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	client := NewHTTPClient()
	defer client.Close()
	ctx := client.WithPolicy(context.Background(), denyPort(port))
	if _, err := DialContext(ctx, "tcp", ln.Addr().String(), "", time.Second, false, "", true); err == nil {
		t.Fatal("TCP 连接应被拒绝")
	}
	proxy, tunnels := httpConnectProxy(t)
	if err := CheckProxy(ctx, proxy, ln.Addr().String(), 2*time.Second); err != nil {
		t.Fatalf("目标被拒绝不应视为代理不可用: %v", err)
	}
	if tunnels.load() != 0 || counted.conns.Load() != 0 {
		t.Fatalf("被拒绝的目标收到了连接: tunnels=%d conns=%d", tunnels.load(), counted.conns.Load())
	}
	var proxyDials atomic.Int32
	allowed := client.WithPolicy(context.Background(), Policy{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyDials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}})
	if err := CheckProxy(allowed, proxy, ln.Addr().String(), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if proxyDials.Load() != 2 || !strings.Contains(proxy, "127.0.0.1") {
		t.Fatalf("代理健康探测应经过策略的 Dial: %d", proxyDials.Load())
	}
}
