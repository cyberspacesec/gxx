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
	resourceMu        sync.Mutex
	resourceHashes    map[[32]byte]*list.Element
	resourceOrder     *list.List
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
	c.resourceHashes, c.resourceOrder = nil, nil
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

	client, err := c.configureClient(options)
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
	ctx = WithCookieJar(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	configureHeaders(req, options)
	client, err := c.configureClient(options)
	if err != nil {
		return nil, err
	}
	resourceClient := *client
	resourceClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
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

// clientKey 区分子客户端：代理决定 Transport，超时与是否跟随重定向决定客户端本身。
type clientKey struct {
	proxy           string
	timeout         time.Duration
	followRedirects bool
}

func (c *HTTPClient) configureClient(options OptionsRequest) (*http.Client, error) {
	key := clientKey{options.Proxy, options.Timeout, options.FollowRedirects}
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
	transport, err := c.createTransport(options.Proxy)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport:     &requestTransport{base: wrapTransport(transport, c.debugHTTP.Load()), owner: c},
		Timeout:       options.Timeout,
		CheckRedirect: createRedirectPolicy(options.FollowRedirects),
	}
	c.clientCache.Store(key, client)
	return client, nil
}

// createTransport 返回代理对应的 Transport，调用方持有 c.mu。
func (c *HTTPClient) createTransport(proxyURL string) (*http.Transport, error) {
	if cachedTransport, found := c.transportCache.Load(proxyURL); found {
		return cachedTransport.(*http.Transport), nil
	}
	dial, err := c.targetDialer(proxyURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig:       c.tlsConfig.Clone(),
		DialContext:           dial,
		TLSHandshakeTimeout:   DefaultTimeout,
		ResponseHeaderTimeout: 0,
		MaxIdleConns:          keepAliveMaxIdle,
		MaxIdleConnsPerHost:   keepAliveMaxIdlePerHost,
		MaxConnsPerHost:       keepAliveMaxConnsPerHost,
		IdleConnTimeout:       keepAliveIdleTimeout,
		DisableKeepAlives:     c.keepAliveDisabled.Load(),
	}
	c.transportCache.Store(proxyURL, transport)
	return transport, nil
}

// targetDialer 返回连接目标 host:port 的拨号函数：直连，或经代理建立到目标的隧道。
// HTTP 请求始终为 TCP；UDP 仅出现在 TCP/UDP 规则路径（见 network.DialContext）。
// 宽松回退与 Transport 使用同一个拨号函数，不存在绕过代理的连接。
func (c *HTTPClient) targetDialer(proxyURL string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if proxyURL == "" {
		return (&net.Dialer{Timeout: DefaultTimeout, KeepAlive: 30 * time.Second}).DialContext, nil
	}
	proxy, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	switch proxyBaseScheme(proxy) {
	case schemeHTTP, schemeHTTPS:
		// HTTP(S) 代理走自实现的 CONNECT 拨号，修正 proxyclient 的 ctx/超时与错误传播问题。
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialHTTPConnect(ctx, network, addr, proxy, DefaultDialTimeout)
		}, nil
	default:
		dialer, derr := proxyclient.NewClient(applyProxyTLSDefaults(proxy))
		if derr != nil {
			return nil, fmt.Errorf("创建代理客户端失败: %v", derr)
		}
		return dialer.DialContext, nil
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

// requestTransport 对重试、重定向及普通请求逐次收费。
type requestTransport struct {
	base  http.RoundTripper
	owner *HTTPClient
}

func (t *requestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.owner.WaitRequest(req.Context(), req.URL.String()); err != nil {
		return nil, err
	}
	// Cookie 会话来自请求的 ctx（见 WithCookieJar）。重定向的每一跳都经过这里，
	// 上一跳设置的 Cookie 会带到下一跳。附加 Cookie 时复制请求，不修改调用方的请求。
	jar := cookieJarFrom(req.Context())
	if jar != nil {
		if cookies := jar.Cookies(req.URL); len(cookies) > 0 {
			req = req.Clone(req.Context())
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
		}
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && jar != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			jar.SetCookies(req.URL, cookies)
		}
	}
	return resp, err
}
