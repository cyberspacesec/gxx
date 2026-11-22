/*
Package network Client 提供实例化的 HTTP 客户端。

每个 Client 持有独立的 TLS 配置、Transport 缓存与 http.Client 缓存，
多个 Engine / Runner 可并发使用各自实例，互不干扰。
*/
package network

import (
	"container/list"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/cyberspacesec/gxx/utils/logger"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proxyclient"
	"golang.org/x/time/rate"
)

// HTTPClient 实例化 HTTP 客户端，持有按 (proxy, timeout, followRedirects) 键缓存的子客户端。
type HTTPClient struct {
	mu                sync.Mutex
	limiter           *HostRateLimiter
	global            *rate.Limiter
	tlsConfig         *tls.Config
	transportCache    sync.Map
	clientCache       sync.Map
	keepAliveDisabled atomic.Bool
	debugHTTP         atomic.Bool
	closed            atomic.Bool
	policy            atomic.Pointer[Policy]
	resourceMu        sync.Mutex
	resourceHashes    map[[32]byte]*list.Element
	resourceOrder     *list.List
	resourceBytes     int
}

// NewHTTPClient 创建 HTTP 客户端实例。
func NewHTTPClient() *HTTPClient {
	c := &HTTPClient{}
	c.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       scannerCipherSuites(),
	}
	return c
}

// scannerCipherSuites 返回扫描用的 TLS 1.0–1.2 套件：Go 实现的全部套件，包含已被标记为
// 不安全的 RSA 密钥交换、CBC-SHA256、RC4 等。指纹识别需要尽可能握手成功，包括老旧设备。
//
// 不能手写清单：旧的手写清单漏掉了 ECDSA+AES-GCM，导致使用 ECDSA 证书的现代站点握手失败；
// 也不能改用 Go 默认值：1.22 起默认集已移除 RSA 密钥交换，老旧设备将无法握手。
// 这里直接取标准库的完整列表，随 Go 版本自动保持完整。
func scannerCipherSuites() []uint16 {
	secure, insecure := tls.CipherSuites(), tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(secure)+len(insecure))
	for _, suite := range secure {
		ids = append(ids, suite.ID)
	}
	for _, suite := range insecure {
		ids = append(ids, suite.ID)
	}
	return ids
}

// SetHTTPDebug 启用 HTTP 原始报文 dump（仅 Debug 模式应开启）。
func (c *HTTPClient) SetHTTPDebug(enabled bool) {
	c.debugHTTP.Store(enabled)
}

// SetDisableKeepAlives 控制后续新建 Transport 是否禁用 Keep-Alive。
// 已缓存的 Transport 保持原行为。
func (c *HTTPClient) SetDisableKeepAlives(disabled bool) {
	c.keepAliveDisabled.Store(disabled)
}

// SetInsecureSkipVerify 更新 TLS 证书校验策略（仅影响后续新建的 Transport）。
func (c *HTTPClient) SetInsecureSkipVerify(skip bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tlsConfig != nil {
		c.tlsConfig.InsecureSkipVerify = skip
	}
}

// transportTLSConfig 返回扫描 TLS 配置的独立副本。
func (c *HTTPClient) transportTLSConfig() *tls.Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tlsConfig.Clone()
}

// Close 关闭所有缓存 Transport 的空闲连接并清空缓存。
func (c *HTTPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.resourceMu.Lock()
	c.resourceHashes, c.resourceOrder, c.resourceBytes = nil, nil, 0
	c.resourceMu.Unlock()
	c.transportCache.Range(func(key, value any) bool {
		if transport, ok := value.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		c.transportCache.Delete(key)
		return true
	})
	c.clientCache.Range(func(key, value any) bool {
		c.clientCache.Delete(key)
		return true
	})
	return nil
}

func (c *HTTPClient) SetRateLimiter(limiter *HostRateLimiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limiter = limiter
}

// SetGlobalRateLimiter 设置实例发出的全部请求共用的总速率限制；nil 表示不限制。
func (c *HTTPClient) SetGlobalRateLimiter(limiter *rate.Limiter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.global = limiter
}

// WaitRequest 在每次实际发出请求前调用：先等待总速率的名额，再等待目标主机的名额。
func (c *HTTPClient) WaitRequest(ctx context.Context, target string) error {
	c.mu.Lock()
	limiter, global := c.limiter, c.global
	closed := c.closed.Load()
	c.mu.Unlock()
	if closed {
		return fmt.Errorf("HTTP 客户端已经关闭")
	}
	if global != nil {
		if err := global.Wait(ctx); err != nil {
			return err
		}
	}
	return limiter.Wait(ctx, target)
}

// SendRequestHttp 按配置发送 HTTP 请求（支持重定向与 POST body 复用）。
func (c *HTTPClient) SendRequestHttp(ctx context.Context, method, urlStr, body string, options OptionsRequest) (*http.Response, error) {
	setDefaults(&options)
	if options.Proxy != "" {
		logger.FromContext(ctx).Debug("使用代理：%s", options.Proxy)
	}
	// 没有会话的独立调用使用一次性会话，覆盖本次请求的重定向链。
	ctx = WithCookieJar(ctx)
	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, payload)
	if err != nil {
		return nil, err
	}
	configureHeaders(req, options)

	client, err := c.configureClient(ctx, options)
	if err != nil {
		return nil, err
	}

	// 跟随重定向的 GET 与入口探测直接走标准客户端：不重试，也不启用畸形响应的
	// 宽松回退，非 HTTP 服务不会被回退路径伪装成一次成功的响应。
	if method == http.MethodGet && (options.FollowRedirects || options.Probe) {
		return client.Do(req)
	}
	return c.doWithRetry(client, req, options)
}

// GetResource 使用原始 URL 获取页面资源（图标），保留签名查询串的顺序和编码。
// HTTP 客户端、连接池、代理与限速由当前实例管理，Cookie 会话来自 ctx。
//
// 资源请求按浏览器的方式跟随重定向，可以跨主机（图标常托管在 CDN），最多
// maxRedirects 跳；离开请求的源之后不再携带自定义请求头。
func (c *HTTPClient) GetResource(ctx context.Context, rawURL string, options OptionsRequest) (*http.Response, error) {
	setDefaults(&options)
	ctx = withKind(WithCookieJar(ctx), RequestIcon)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	configureHeaders(req, options)
	client, err := c.configureClient(ctx, options)
	if err != nil {
		return nil, err
	}
	resourceClient := *client
	resourceClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects || !c.RedirectAllowed(next.Context(), via[len(via)-1].URL, next.URL) {
			return http.ErrUseLastResponse
		}
		if !SameOrigin(req.URL, next.URL) {
			for key := range options.CustomHeaders {
				switch http.CanonicalHeaderKey(key) {
				case "User-Agent", "Accept", "Accept-Language":
				default:
					next.Header.Del(key)
				}
			}
			next.Header.Del("Referer")
			if req.URL.Scheme != "https" || next.URL.Scheme == "https" {
				next.Header.Set("Referer", req.URL.Scheme+"://"+req.URL.Host+"/")
			}
		}
		return nil
	}
	return resourceClient.Do(req)
}

// ResourceCookies 返回 ctx 会话中将发往 rawURL 的 Cookie 快照，供内容缓存隔离。
func (c *HTTPClient) ResourceCookies(ctx context.Context, rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	jar := cookieJarFrom(ctx)
	if err != nil || jar == nil {
		return nil
	}
	return jar.Cookies(u)
}

// clientKey 区分子客户端：代理与是否独立拨号决定 Transport，超时与是否跟随重定向决定客户端本身。
type clientKey struct {
	proxy           string
	timeout         time.Duration
	followRedirects bool
	scoped          bool
}

// transportKey 区分 Transport。scoped 的 Transport 不复用连接，拨号使用 ctx 中的策略。
type transportKey struct {
	proxy  string
	scoped bool
}

func (c *HTTPClient) configureClient(ctx context.Context, options OptionsRequest) (*http.Client, error) {
	_, state := c.policyFor(ctx)
	key := clientKey{options.Proxy, options.Timeout, options.FollowRedirects, state != nil && state.scoped}
	if cached, ok := c.clientCache.Load(key); ok && !c.closed.Load() {
		return cached.(*http.Client), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, fmt.Errorf("HTTP 客户端已经关闭")
	}
	if cached, ok := c.clientCache.Load(key); ok {
		return cached.(*http.Client), nil
	}
	transport, err := c.createTransport(transportKey{options.Proxy, key.scoped})
	if err != nil {
		return nil, err
	}
	base := wrapTransport(transport, c.debugHTTP.Load())
	engine := base
	if wrap := c.Policy().WrapTransport; wrap != nil {
		if wrapped := wrap(base); wrapped != nil {
			engine = wrapped
		}
	}
	client := &http.Client{
		Transport:     &requestTransport{base: base, engine: engine, owner: c},
		Timeout:       options.Timeout,
		CheckRedirect: c.redirectPolicy(options.FollowRedirects),
	}
	c.clientCache.Store(key, client)
	return client, nil
}

// createTransport 返回 key 对应的 Transport，调用方持有 c.mu。
func (c *HTTPClient) createTransport(key transportKey) (*http.Transport, error) {
	if cachedTransport, found := c.transportCache.Load(key); found {
		return cachedTransport.(*http.Transport), nil
	}
	dial, err := c.targetDialer(key.proxy, key.scoped)
	if err != nil {
		return nil, err
	}
	tlsConfig := c.tlsConfig.Clone()
	transport := &http.Transport{
		// 连接由这里建立并包装：明文连接记录响应头顺序；HTTPS 连接在这里完成握手，
		// 同时旁路记录 ServerHello，握手状态由 requestTransport 填回 resp.TLS。
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return newTrackedConn(conn, nil, nil), nil
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			config := tlsConfig.Clone()
			if config.ServerName == "" {
				if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
					config.ServerName = host
				}
			}
			handshakeCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
			defer cancel()
			secure, recorder, err := handshakeTLS(handshakeCtx, conn, config)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return newTrackedConn(secure, secure, recorder), nil
		},
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   DefaultTimeout,
		ResponseHeaderTimeout: 0,
		MaxIdleConns:          keepAliveMaxIdle,
		MaxIdleConnsPerHost:   keepAliveMaxIdlePerHost,
		MaxConnsPerHost:       keepAliveMaxConnsPerHost,
		IdleConnTimeout:       keepAliveIdleTimeout,
		DisableKeepAlives:     c.keepAliveDisabled.Load() || key.scoped,
	}
	c.transportCache.Store(key, transport)
	return transport, nil
}

// baseDial 返回连接目标或代理服务器所用的策略拨号函数。scoped 时取 ctx 中的策略：
// 这类 Transport 不复用连接，连接只属于发起它的请求。
func (c *HTTPClient) baseDial(ctx context.Context, scoped bool) dialFunc {
	if scoped {
		if dial := PolicyFrom(ctx).Dial; dial != nil {
			return dial
		}
	}
	return c.Policy().Dial
}

// targetDialer 返回连接目标 host:port 的拨号函数：直连，或经代理建立到目标的隧道。
// HTTP 请求始终为 TCP；UDP 仅出现在 TCP/UDP 规则路径（见 network.DialContext）。
// 宽松回退与 Transport 使用同一个拨号函数，不存在绕过代理或网络策略的连接。
func (c *HTTPClient) targetDialer(proxyURL string, scoped bool) (dialFunc, error) {
	if proxyURL == "" {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return policyDialer(c.baseDial(ctx, scoped), DefaultTimeout, 30*time.Second)(ctx, network, addr)
		}, nil
	}
	proxy, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	switch proxyBaseScheme(proxy) {
	case schemeHTTP, schemeHTTPS:
		// HTTP(S) 代理走自实现的 CONNECT 拨号，修正 proxyclient 的 ctx/超时与错误传播问题。
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialHTTPConnect(ctx, network, addr, proxy, DefaultDialTimeout, policyDialer(c.baseDial(ctx, scoped), DefaultDialTimeout, 0))
		}, nil
	default:
		upstream := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return policyDialer(c.baseDial(ctx, scoped), DefaultTimeout, 0)(ctx, network, addr)
		}
		dialer, derr := proxyclient.NewClientWithDial(applyProxyTLSDefaults(proxy), upstream)
		if derr != nil {
			return nil, fmt.Errorf("创建代理客户端失败: %v", derr)
		}
		return dialer.DialContext, nil
	}
}

// redirectPolicy 创建页面请求的重定向策略：跟随 HTTP 30x，最多 maxRedirects 跳。
//
// 30x 可以指向其他主机、协议或端口（www 与裸域名、http 与 https 之间的跳转都属于
// 这种情况）。离开发起请求的源之后只保留浏览器的通用请求头：自定义请求头、认证
// 信息不会发给其他主机。达到跳数上限或网络策略不允许时返回最后一个 30x 响应。
// 请求体由 net/http 按状态码处理：307/308 重放原请求体，301/302/303 改为不带请求体的 GET。
func (c *HTTPClient) redirectPolicy(followRedirects bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects || len(via) >= maxRedirects || !c.RedirectAllowed(req.Context(), via[len(via)-1].URL, req.URL) {
			return http.ErrUseLastResponse
		}
		if !SameOrigin(via[0].URL, req.URL) {
			KeepPortableHeaders(req.Header)
		}
		return nil
	}
}

// loggingTransport 包装底层 RoundTripper，输出成对的请求/响应原始数据。
type loggingTransport struct {
	base http.RoundTripper
}

func wrapTransport(base http.RoundTripper, debug bool) http.RoundTripper {
	if debug && base != nil {
		return &loggingTransport{base: base}
	}
	return base
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if dumpReq, err := httputil.DumpRequestOut(req, false); err == nil {
		logger.FromContext(req.Context()).Debug("[HTTP] 原始请求(不含Body):\n%s", strings.TrimSpace(string(dumpReq)))
	} else {
		logger.FromContext(req.Context()).Debug("[HTTP] 原始请求转储失败: %v", err)
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	if resp != nil {
		if dumpResp, err := httputil.DumpResponse(resp, false); err == nil {
			logger.FromContext(req.Context()).Debug("[HTTP] 原始响应头(不含Body):\n%s", strings.TrimSpace(string(dumpResp)))
		} else {
			logger.FromContext(req.Context()).Debug("[HTTP] 原始响应头转储失败: %v", err)
		}
	}
	return resp, nil
}

// requestTransport 对重试、重定向及普通请求逐次检查目标并收费。
// base 是未经策略包装的底层，engine 是客户端级 WrapTransport 包装后的结果；
// ctx 中的策略覆盖了 WrapTransport 时改用覆盖结果包装 base。
type requestTransport struct {
	base   http.RoundTripper
	engine http.RoundTripper
	owner  *HTTPClient
}

func (t *requestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	policy, state := t.owner.policyFor(ctx)
	info := RequestInfoFrom(ctx)
	if info.Kind == "" {
		info.Kind = RequestHTTP
	}
	// 重定向的每一跳由 net/http 新建请求，Response 字段指向发出跳转的响应。
	redirect := req.Response != nil
	rec := RecorderFrom(ctx)
	if rec != nil && rec.Full() {
		rec = nil
	}
	start := time.Now()
	if err := checkTarget(ctx, policy, urlTarget(info.Kind, req.URL, info, redirect)); err != nil {
		if rec != nil {
			rec.failed(rec.requestExchange(ctx, info.Kind, req, redirect), start, err)
		}
		return nil, err
	}
	if err := t.owner.WaitRequest(ctx, req.URL.String()); err != nil {
		if rec != nil {
			rec.failed(rec.requestExchange(ctx, info.Kind, req, redirect), start, err)
		}
		return nil, err
	}
	// Cookie 会话来自请求的 ctx（见 WithCookieJar）。重定向的每一跳都经过这里，
	// 上一跳设置的 Cookie 会带到下一跳。附加 Cookie 时复制请求，不修改调用方的请求。
	jar := cookieJarFrom(ctx)
	if jar != nil {
		if cookies := jar.Cookies(req.URL); len(cookies) > 0 {
			req = req.Clone(ctx)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
		}
	}
	var ex Exchange
	if rec != nil {
		ex = rec.requestExchange(ctx, info.Kind, req, redirect)
		start = time.Now()
	}
	rt := t.engine
	if state != nil && state.override != nil {
		rt = state.wrappedFor(t.base)
	}
	// 取得本次请求实际使用的连接，读取握手摘要与响应头顺序。摘要随 resp.Request 的 ctx
	// 交给调用方（见 ResponseDetails）。GotConn 在调用 RoundTrip 的协程中触发。
	details := &responseDetails{}
	var used net.Conn
	traced := httptrace.WithClientTrace(context.WithValue(ctx, responseDetailsKey{}, details), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { used = info.Conn },
	})
	resp, err := rt.RoundTrip(req.WithContext(traced))
	if err != nil {
		if rec != nil {
			rec.failed(ex, start, err)
		}
		return resp, err
	}
	if tracked, ok := used.(*trackedConn); ok {
		details.headerOrder = tracked.takeHeaderOrder()
		if tracked.tls != nil {
			details.tls, details.secure = tracked.tls.info, true
			if resp.TLS == nil {
				resp.TLS = &tracked.tls.state
			}
		}
	}
	if jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			jar.SetCookies(req.URL, cookies)
		}
	}
	if rec != nil {
		rec.observeResponse(ex, resp, details.headerOrder, start)
	}
	return resp, nil
}

type responseDetailsKey struct{}

// responseDetails 是 Transport 读取一个响应时记录的连接信息。
type responseDetails struct {
	headerOrder []string
	tls         TLSInfo
	secure      bool
}

// ResponseHeaderOrder 返回响应头名称按服务器发送的顺序（保留重复与原始大小写）；
// 响应不是经当前客户端读取的，或无法记录时返回 nil。
func ResponseHeaderOrder(resp *http.Response) []string {
	if details := detailsOf(resp); details != nil {
		return details.headerOrder
	}
	return nil
}

// ResponseTLS 返回响应所在连接的握手摘要；明文连接或未知时返回 false。
func ResponseTLS(resp *http.Response) (TLSInfo, bool) {
	if details := detailsOf(resp); details != nil && details.secure {
		return details.tls, true
	}
	if resp != nil && resp.TLS != nil {
		return tlsSummary(resp.TLS, ServerHello{}, false), true
	}
	return TLSInfo{}, false
}

// AttachResponseDetails 让由 src 派生的响应 dst（如按已读取的页面重建的响应）
// 携带 src 的连接信息与握手状态。
func AttachResponseDetails(dst, src *http.Response) {
	if dst == nil || src == nil {
		return
	}
	if dst.TLS == nil {
		dst.TLS = src.TLS
	}
	details := detailsOf(src)
	if details == nil || dst.Request == nil {
		return
	}
	dst.Request = dst.Request.WithContext(context.WithValue(dst.Request.Context(), responseDetailsKey{}, details))
}

func detailsOf(resp *http.Response) *responseDetails {
	if resp == nil || resp.Request == nil {
		return nil
	}
	details, _ := resp.Request.Context().Value(responseDetailsKey{}).(*responseDetails)
	return details
}
