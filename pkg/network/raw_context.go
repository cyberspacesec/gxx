package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	rawclient "github.com/projectdiscovery/rawhttp/client"
)

type rawResponseBody struct {
	io.Reader
	ctx  context.Context
	conn net.Conn
	stop func() bool
	once sync.Once
}

// Read 不把取消后仍留在协议缓冲中的数据作为成功响应交给规则。
func (b *rawResponseBody) Read(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := b.Reader.Read(p)
	if contextErr := b.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func (b *rawResponseBody) Close() error {
	var err error
	b.once.Do(func() { b.stop(); err = b.conn.Close() })
	return err
}

// SendRawRequest 使用原始 HTTP 编解码器，同时保持请求取消、代理和逐次限流。
func (c *HTTPClient) SendRawRequest(ctx context.Context, rawText, baseURL string, options OptionsRequest) (*http.Response, error) {
	setDefaults(&options)
	parsed, err := Parse(rawText, baseURL, true)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("无效的 Raw HTTP 目标: %s", baseURL)
	}
	headers := make(map[string]string, len(parsed.Headers)+len(options.CustomHeaders)+1)
	for k, v := range parsed.Headers {
		headers[k] = v
	}
	for k, v := range options.CustomHeaders {
		headers[k] = v
	}
	policy := c.PolicyFor(ctx)
	info := RequestInfoFrom(ctx)
	for redirects := 0; ; redirects++ {
		if u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("无效的 Raw HTTP 重定向: %s", u)
		}
		// 先检查目标再计入限速：被策略拒绝的请求不占用名额。
		if err = checkTarget(ctx, policy, urlTarget(RequestRaw, u, info, redirects > 0)); err != nil {
			return nil, err
		}
		if err = c.WaitRequest(ctx, u.String()); err != nil {
			return nil, err
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		conn, err := dialTarget(ctx, policy, nil, "tcp", net.JoinHostPort(u.Hostname(), port), options.Proxy, options.Timeout, u.Scheme == "https", u.Hostname(), options.InsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		deadline := time.Now().Add(options.Timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		wire := rawclient.NewClient(conn)
		hs := make([]rawclient.Header, 0, len(headers)+1)
		for k, v := range headers {
			if !strings.EqualFold(k, "Host") && !strings.EqualFold(k, "Content-Length") {
				hs = append(hs, rawclient.Header{Key: k, Value: v})
			}
		}
		hs = append(hs, rawclient.Header{Key: "Host", Value: u.Host})
		path := parsed.Path
		if redirects > 0 {
			path = u.RequestURI()
		}
		if path == "" {
			path = "/"
		}
		req := &rawclient.Request{Method: parsed.Method, Path: path, Version: rawclient.HTTP_1_1, Headers: hs, Body: strings.NewReader(parsed.Data), AutomaticContentLength: true}
		if err = wire.WriteRequest(req); err != nil {
			stop()
			_ = conn.Close()
			return nil, err
		}
		response, err := wire.ReadResponse(false)
		// TLS 关闭通知可能使服务端结束请求并返回已缓冲的响应；取消优先。
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		}
		if err != nil {
			stop()
			_ = conn.Close()
			return nil, err
		}
		h := make(http.Header, len(response.Headers))
		details := &responseDetails{headerOrder: make([]string, 0, len(response.Headers))}
		for _, v := range response.Headers {
			h.Add(v.Key, v.Value)
			details.headerOrder = append(details.headerOrder, v.Key)
		}
		var state *tls.ConnectionState
		details.tls, state, details.secure = ConnTLSInfo(conn)
		var body io.Reader = response.Body
		if parsed.Method == http.MethodHead {
			body = http.NoBody
		}
		resp := &http.Response{StatusCode: response.Status.Code, Status: strconv.Itoa(response.Status.Code) + " " + response.Status.Reason, Proto: response.Version.String(), ProtoMajor: response.Version.Major, ProtoMinor: response.Version.Minor, Header: h, ContentLength: response.ContentLength(), Body: &rawResponseBody{Reader: body, ctx: ctx, conn: conn, stop: stop}, TLS: state, Request: (&http.Request{Method: parsed.Method, URL: u, Header: make(http.Header)}).WithContext(context.WithValue(ctx, responseDetailsKey{}, details))}
		if options.FollowRedirects && response.Status.IsRedirect() && h.Get("Location") != "" && redirects < maxRedirects {
			next, err := u.Parse(h.Get("Location"))
			// Location 无法解析时返回 30x 响应本身。
			if err == nil && next.Host != "" && (next.Scheme == "http" || next.Scheme == "https") && redirectAllowed(ctx, policy, u, next) {
				_ = resp.Body.Close()
				// 离开原来的源之后只带通用请求头，规则里手写的请求头不发给其他主机。
				if !SameOrigin(u, next) {
					for key := range headers {
						switch http.CanonicalHeaderKey(key) {
						case "User-Agent", "Accept", "Accept-Language":
						default:
							delete(headers, key)
						}
					}
				}
				// 与浏览器一致：301/302/303 之后改用不带请求体的 GET，307/308 保持原请求。
				if code := response.Status.Code; code != http.StatusTemporaryRedirect && code != http.StatusPermanentRedirect && parsed.Method != http.MethodGet && parsed.Method != http.MethodHead {
					parsed.Method, parsed.Data = http.MethodGet, ""
					for key := range headers {
						if strings.EqualFold(key, "Content-Type") {
							delete(headers, key)
						}
					}
				}
				u = next
				continue
			}
		}
		return resp, nil
	}
}
