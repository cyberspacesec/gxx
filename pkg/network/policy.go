package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RequestKind 是一次出站连接的用途。
type RequestKind string

const (
	RequestHTTP     RequestKind = "http"     // 入口、跳转与 HTTP 规则请求
	RequestRaw      RequestKind = "raw"      // Raw HTTP 规则请求
	RequestTCP      RequestKind = "tcp"      // TCP 规则与 TCP 连通性检查
	RequestUDP      RequestKind = "udp"      // UDP 规则
	RequestIcon     RequestKind = "icon"     // 页面图标
	RequestResource RequestKind = "resource" // 页面附属资源：robots.txt、sitemap.xml、标题脚本
	RequestTLS      RequestKind = "tls"      // TLS 指纹探测（JARM）
)

// TargetRequest 描述一次即将发往目标的连接，供 NetworkPolicy.CheckTarget 判断。
//
// Host 是未解析的主机名或字面 IP；需要按解析后的地址判断时在 Dial 中实现。
// 经 socks5/socks5h 代理时域名由代理解析，本端无法检查解析后的地址。
type TargetRequest struct {
	Kind     RequestKind
	Network  string // tcp / udp
	Host     string // 未解析的主机名或字面 IP
	Port     string
	URL      *url.URL // HTTP、Raw、图标、附属资源时非空
	RuleID   string   // 规则请求时为规则标识
	Redirect bool     // 是否为跳转产生的下一跳
}

// RedirectAction 是 NetworkPolicy.Redirect 对一次跳转的决定。
type RedirectAction int

const (
	RedirectFollow RedirectAction = iota // 跟随
	RedirectStop                         // 不访问下一跳，保留发出跳转的响应
)

// Policy 约束引擎的全部出站连接：HTTP、Raw HTTP、TCP、UDP、图标、附属资源、
// 跳转、TLS 探测与代理健康探测。各字段为 nil 时保持默认行为。
type Policy struct {
	// Dial 替代直连拨号。配置代理时用于连接代理服务器本身。ctx 只约束建立连接的过程。
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// CheckTarget 在每次发往目标之前调用（含重试、跳转与经代理隧道的目标）；
	// 返回错误即拒绝，不会有任何字节发往该目标。
	CheckTarget func(ctx context.Context, request TargetRequest) error
	// Redirect 决定引擎本会跟随的 30x、刷新与脚本跳转是否跟随。它只能阻止跟随：
	// 引擎本来不会访问的跳转（如指向其他资产的刷新与脚本跳转）不会因 RedirectFollow 被访问。
	Redirect func(ctx context.Context, from, to *url.URL) RedirectAction
	// WrapTransport 包装 HTTP 请求的底层 RoundTripper（图标与附属资源同样经过它），
	// Raw HTTP、TCP、UDP 与 TLS 探测不经过 RoundTripper。
	WrapTransport func(base http.RoundTripper) http.RoundTripper
}

// IsZero 报告策略是否没有任何约束。
func (p Policy) IsZero() bool {
	return p.Dial == nil && p.CheckTarget == nil && p.Redirect == nil && p.WrapTransport == nil
}

// mergePolicy 逐字段覆盖：override 中非 nil 的字段替换 base 的同名字段。
func mergePolicy(base, override Policy) Policy {
	if override.Dial != nil {
		base.Dial = override.Dial
	}
	if override.CheckTarget != nil {
		base.CheckTarget = override.CheckTarget
	}
	if override.Redirect != nil {
		base.Redirect = override.Redirect
	}
	if override.WrapTransport != nil {
		base.WrapTransport = override.WrapTransport
	}
	return base
}

// DeniedError 是 CheckTarget 拒绝的连接。
type DeniedError struct {
	Request TargetRequest
	Err     error
}

func (e *DeniedError) Error() string {
	target := net.JoinHostPort(e.Request.Host, e.Request.Port)
	if e.Request.URL != nil {
		target = e.Request.URL.Redacted()
	}
	return fmt.Sprintf("网络策略拒绝连接 %s（%s）: %v", target, e.Request.Kind, e.Err)
}

func (e *DeniedError) Unwrap() error { return e.Err }

// policyState 是 ctx 中的生效策略。scoped 表示 Dial 来自请求级覆盖：这类请求使用
// 不复用连接的 Transport，使一次扫描拨出的连接不会被其他扫描取用。
type policyState struct {
	policy   Policy
	scoped   bool
	override func(base http.RoundTripper) http.RoundTripper
	mu       sync.Mutex
	wrapped  map[http.RoundTripper]http.RoundTripper
}

type policyKey struct{}

// WithPolicy 让 ctx 下经当前客户端发出的请求使用 override 逐字段覆盖后的策略：
// override 中非 nil 的字段替换客户端策略的同名字段，nil 字段沿用客户端策略。
// TCP、UDP、Raw HTTP 与代理检查同样从 ctx 读取该策略。
//
// override 设置了 Dial 时，这些 HTTP 请求的连接不进入连接池，不同扫描的拨号互不混用。
// 已缓存的 Transport 照常复用，不为每次调用新建 Transport。
func (c *HTTPClient) WithPolicy(ctx context.Context, override Policy) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	effective := mergePolicy(c.Policy(), override)
	if effective.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, policyKey{}, &policyState{policy: effective, scoped: override.Dial != nil, override: override.WrapTransport})
}

// PolicyFrom 返回 ctx 中生效的策略；没有时为零值。
func PolicyFrom(ctx context.Context) Policy {
	if ctx == nil {
		return Policy{}
	}
	if state, ok := ctx.Value(policyKey{}).(*policyState); ok {
		return state.policy
	}
	return Policy{}
}

// PolicyFor 返回 ctx 下请求的生效策略：ctx 中有覆盖时使用覆盖结果，否则使用客户端策略。
func (c *HTTPClient) PolicyFor(ctx context.Context) Policy {
	policy, _ := c.policyFor(ctx)
	return policy
}

func (c *HTTPClient) policyFor(ctx context.Context) (Policy, *policyState) {
	if ctx != nil {
		if state, ok := ctx.Value(policyKey{}).(*policyState); ok {
			return state.policy, state
		}
	}
	return c.Policy(), nil
}

// Policy 返回客户端级策略。
func (c *HTTPClient) Policy() Policy {
	if p := c.policy.Load(); p != nil {
		return *p
	}
	return Policy{}
}

// SetPolicy 设置客户端级策略并丢弃已缓存的客户端与 Transport，应在发出请求之前调用。
func (c *HTTPClient) SetPolicy(policy Policy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy.Store(&policy)
	c.transportCache.Range(func(key, value any) bool {
		if transport, ok := value.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		c.transportCache.Delete(key)
		return true
	})
	c.clientCache.Range(func(key, _ any) bool {
		c.clientCache.Delete(key)
		return true
	})
}

// wrappedFor 返回请求级 WrapTransport 包装后的 RoundTripper，每个底层只包装一次。
func (s *policyState) wrappedFor(base http.RoundTripper) http.RoundTripper {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.wrapped[base]; ok {
		return rt
	}
	if s.wrapped == nil {
		s.wrapped = make(map[http.RoundTripper]http.RoundTripper, 1)
	}
	rt := s.override(base)
	if rt == nil {
		rt = base
	}
	s.wrapped[base] = rt
	return rt
}

// RequestInfo 标注 ctx 下请求的用途与所属规则，供网络策略与交换观察使用。
type RequestInfo struct {
	Kind     RequestKind
	RuleID   string
	SubRule  string
	Redirect bool
}

type requestInfoKey struct{}

// WithRequestInfo 标注 ctx 下请求的用途与所属规则。
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFrom 返回 ctx 的请求标注；没有时为零值。
func RequestInfoFrom(ctx context.Context) RequestInfo {
	if ctx == nil {
		return RequestInfo{}
	}
	info, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info
}

// WithRequestKind 保留 ctx 中的规则标注，只改变用途。
func WithRequestKind(ctx context.Context, kind RequestKind) context.Context {
	return withKind(ctx, kind)
}

// WithRedirectHop 把 ctx 下的请求标注为跳转产生的下一跳。
func WithRedirectHop(ctx context.Context) context.Context {
	info := RequestInfoFrom(ctx)
	if info.Redirect {
		return ctx
	}
	info.Redirect = true
	return WithRequestInfo(ctx, info)
}

// withKind 保留 ctx 中的规则标注，只改变用途。
func withKind(ctx context.Context, kind RequestKind) context.Context {
	info := RequestInfoFrom(ctx)
	if info.Kind == kind {
		return ctx
	}
	info.Kind = kind
	return WithRequestInfo(ctx, info)
}

// checkTarget 按生效策略检查一次即将发出的连接。
func checkTarget(ctx context.Context, policy Policy, request TargetRequest) error {
	if policy.CheckTarget == nil {
		return nil
	}
	if err := policy.CheckTarget(ctx, request); err != nil {
		return &DeniedError{Request: request, Err: err}
	}
	return nil
}

// urlTarget 由请求地址构造检查参数，省略的端口按协议补全。
func urlTarget(kind RequestKind, u *url.URL, info RequestInfo, redirect bool) TargetRequest {
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return TargetRequest{Kind: kind, Network: "tcp", Host: u.Hostname(), Port: port, URL: u, RuleID: info.RuleID, Redirect: redirect || info.Redirect}
}

// addressTarget 由 host:port 构造检查参数。
func addressTarget(kind RequestKind, network, address string, info RequestInfo) TargetRequest {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	return TargetRequest{Kind: kind, Network: strings.ToLower(network), Host: host, Port: port, RuleID: info.RuleID, Redirect: info.Redirect}
}

// dialFunc 是建立连接的函数。
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// policyDialer 返回带超时的拨号函数：策略提供 Dial 时使用它，否则使用 net.Dialer。
// keepAlive 为 0 时使用 net.Dialer 的默认保活。
func policyDialer(dial dialFunc, timeout, keepAlive time.Duration) dialFunc {
	if dial == nil {
		return (&net.Dialer{Timeout: timeout, KeepAlive: keepAlive}).DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		conn, err := dial(ctx, network, address)
		if err == nil && conn == nil {
			return nil, errors.New("网络策略的 Dial 返回了空连接")
		}
		return conn, err
	}
}

// redirectAllowed 询问策略是否跟随一次引擎本会跟随的跳转。
func redirectAllowed(ctx context.Context, policy Policy, from, to *url.URL) bool {
	return policy.Redirect == nil || policy.Redirect(ctx, from, to) != RedirectStop
}

// RedirectAllowed 询问 ctx 下生效的策略是否跟随一次引擎本会跟随的跳转。
func (c *HTTPClient) RedirectAllowed(ctx context.Context, from, to *url.URL) bool {
	return redirectAllowed(ctx, c.PolicyFor(ctx), from, to)
}
