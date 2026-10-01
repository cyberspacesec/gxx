/*
Package network Client 提供实例化的 HTTP 客户端。

每个 Client 持有独立的 TLS 配置、Transport 缓存与 retryablehttp.Client 缓存，
多个 Engine / Runner 可并发使用各自实例，互不干扰。
*/
package network

import (
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/proxyclient"
	"github.com/zan8in/retryablehttp"
	"golang.org/x/net/publicsuffix"
)

// HTTPClient 实例化 HTTP 客户端，持有按 (proxy, timeout, followRedirects) 键缓存的子客户端。
type HTTPClient struct {
	mu                sync.Mutex
	limiter           *HostRateLimiter
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
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	return c
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
func (c *HTTPClient) WaitRequest(ctx context.Context, target string) error {
	c.mu.Lock()
	limiter := c.limiter
	closed := c.closed.Load()
	c.mu.Unlock()
	if closed {
		return fmt.Errorf("HTTP 客户端已经关闭")
	}
	return limiter.Wait(ctx, target)
}

// SendRequestHttp 按配置发送 HTTP 请求（支持重定向与 POST body 复用）。
func (c *HTTPClient) SendRequestHttp(ctx context.Context, method, urlStr, body string, options OptionsRequest) (*http.Response, error) {
	setDefaults(&options)
	if options.Proxy != "" {
		logger.FromContext(ctx).Debug("使用代理：%s", options.Proxy)
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	configureHeaders(req, options)

	if body != "" && req.Request.GetBody == nil {
		bodyBytes := []byte(body)
		req.Request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		req.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.Request.ContentLength = int64(len(bodyBytes))
	}

	client, err := c.configureClient(options)
	if err != nil {
		return nil, err
	}

	if options.FollowRedirects && method == "GET" {
		httpReq := req.Request
		if httpReq.GetBody == nil {
			httpReq.GetBody = func() (io.ReadCloser, error) {
				return http.NoBody, nil
			}
		}
		return client.HTTPClient.Do(httpReq)
	}
	return client.Do(req)
}

// GetResource 使用原始 URL 获取页面资源，保留签名查询串的顺序和编码。
// HTTP 客户端、CookieJar、连接池、代理与限速仍由当前实例管理。
func (c *HTTPClient) GetResource(ctx context.Context, rawURL string, options OptionsRequest) (*http.Response, error) {
	setDefaults(&options)
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	configureHeaders(&retryablehttp.Request{Request: req}, options)
	client, err := c.configureClient(options)
	if err != nil {
		return nil, err
	}
	resourceClient := *client.HTTPClient
	resourceClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if err := client.HTTPClient.CheckRedirect(next, via); err != nil {
			return err
		}
		if !sameResourceOrigin(req.URL, next.URL) {
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

func sameResourceOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// ResourceCookies 返回资源请求所使用会话的 Cookie 快照，供内容缓存隔离。
func (c *HTTPClient) ResourceCookies(rawURL string, options OptionsRequest) []*http.Cookie {
	setDefaults(&options)
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	client, err := c.configureClient(options)
	if err != nil || client.HTTPClient.Jar == nil {
		return nil
	}
	return client.HTTPClient.Jar.Cookies(u)
}

// CheckProtocol 探测目标应使用的 http/https 前缀。
// ctx 取消或 timeout 到期会中断探测；timeout <= 0 时使用 DefaultTimeout。
func (c *HTTPClient) CheckProtocol(ctx context.Context, host, proxy string, timeout time.Duration) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(strings.TrimSpace(host)) == 0 {
		return "", fmt.Errorf("host %q is empty", host)
	}

	if strings.HasPrefix(host, HttpPrefix) || strings.HasPrefix(host, HttpsPrefix) {
		return host, nil
	}

	u, err := url.Parse(HttpPrefix + host)
	if err != nil {
		return "", err
	}

	switch u.Port() {
	case "80":
		return c.checkAndReturnProtocol(ctx, HttpPrefix+host, proxy, timeout)
	case "443":
		return c.checkAndReturnProtocol(ctx, HttpsPrefix+host, proxy, timeout)
	default:
		if result, err := c.checkAndReturnProtocol(ctx, HttpsPrefix+host, proxy, timeout); err == nil {
			return result, nil
		}
		return c.checkAndReturnProtocol(ctx, HttpPrefix+host, proxy, timeout)
	}
}

func (c *HTTPClient) configureClient(options OptionsRequest) (*retryablehttp.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return nil, fmt.Errorf("HTTP 客户端已经关闭")
	}
	key := clientCacheKey(options.Proxy, options.Timeout, options.FollowRedirects)
	if cached, ok := c.clientCache.Load(key); ok {
		return cached.(*retryablehttp.Client), nil
	}

	opts := retryablehttp.DefaultOptionsSingle
	opts.Timeout = options.Timeout

	client := retryablehttp.NewClient(opts)

	transport, err := c.createTransport(options.Proxy)
	if err != nil {
		return nil, err
	} else {
		client.HTTPClient.Transport = &requestTransport{base: wrapTransport(transport, c.debugHTTP.Load()), owner: c}
		client.HTTPClient2.Transport = &requestTransport{base: wrapTransport(transport, c.debugHTTP.Load()), owner: c}
	}

	jar, jerr := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if jerr != nil {
		return nil, fmt.Errorf("创建 CookieJar 失败: %w", jerr)
	} else {
		client.HTTPClient.Jar = jar
		client.HTTPClient2.Jar = jar
	}

	client.HTTPClient.Timeout = options.Timeout
	client.HTTPClient2.Timeout = options.Timeout

	redirectPolicy := createRedirectPolicy(options.FollowRedirects)
	client.HTTPClient.CheckRedirect = redirectPolicy
	client.HTTPClient2.CheckRedirect = redirectPolicy

	c.clientCache.Store(key, client)
	return client, nil
}

func (c *HTTPClient) createTransport(proxyURL string) (*http.Transport, error) {
	if cachedTransport, found := c.transportCache.Load(proxyURL); found {
		return cachedTransport.(*http.Transport), nil
	}

	newBaseTransport := func() *http.Transport {
		return &http.Transport{
			TLSClientConfig:       c.tlsConfig.Clone(),
			DialContext:           (&net.Dialer{Timeout: DefaultTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   DefaultTimeout,
			ResponseHeaderTimeout: 0,
			MaxIdleConns:          keepAliveMaxIdle,
			MaxIdleConnsPerHost:   keepAliveMaxIdlePerHost,
			MaxConnsPerHost:       keepAliveMaxConnsPerHost,
			IdleConnTimeout:       keepAliveIdleTimeout,
			DisableKeepAlives:     c.keepAliveDisabled.Load(),
		}
	}

	var transport *http.Transport
	if proxyURL == "" {
		transport = newBaseTransport()
	} else {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("代理地址解析失败: %v", err)
		}
		dialer, err := proxyclient.NewClient(proxy)
		if err != nil {
			return nil, fmt.Errorf("创建代理客户端失败: %v", err)
		}
		transport = newBaseTransport()
		transport.DialContext = dialer.DialContext
	}

	c.transportCache.Store(proxyURL, transport)
	return transport, nil
}

func (c *HTTPClient) prepareSimpleClient(proxy string, timeout time.Duration) (*retryablehttp.Client, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return c.configureClient(OptionsRequest{
		Proxy:           proxy,
		Timeout:         timeout,
		FollowRedirects: false,
	})
}

func (c *HTTPClient) checkProtocolGet(ctx context.Context, target, proxy string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := c.prepareSimpleClient(proxy, timeout)
	if err != nil {
		return "", err
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := retryablehttp.NewRequestWithContext(reqCtx, http.MethodHead, target, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("User-Agent", common.RandomUA())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.TLS != nil {
		return "https", nil
	}
	return "http", nil
}

func (c *HTTPClient) checkAndReturnProtocol(ctx context.Context, urlStr, proxy string, timeout time.Duration) (string, error) {
	if urlStr == "" {
		return "", errors.New("URL不能为空")
	}

	res, err := c.checkProtocolGet(ctx, urlStr, proxy, timeout)
	if err != nil {
		return "", fmt.Errorf("检查协议失败: %w", err)
	}

	if res == "https" {
		if strings.HasPrefix(urlStr, HttpsPrefix) {
			return urlStr, nil
		}
		if strings.HasPrefix(urlStr, HttpPrefix) {
			return HttpsPrefix + urlStr[len(HttpPrefix):], nil
		}
		return HttpsPrefix + urlStr, nil
	}

	if strings.HasPrefix(urlStr, HttpPrefix) || strings.HasPrefix(urlStr, HttpsPrefix) {
		return urlStr, nil
	}
	return HttpPrefix + urlStr, nil
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
	return t.base.RoundTrip(req)
}
