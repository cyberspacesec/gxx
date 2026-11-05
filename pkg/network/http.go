/*
Package network 提供 HTTP 请求、协议探测与请求解析工具。
*/
package network

import (
	"bytes"
	"fmt"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/proto"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zan8in/retryablehttp"
)

// Keep-Alive 连接池参数。
const (
	keepAliveMaxIdle         = 100
	keepAliveMaxIdlePerHost  = 10
	keepAliveMaxConnsPerHost = 30
	keepAliveIdleTimeout     = 90 * time.Second
)

// 请求体与超时默认值。
const (
	MaxDefaultBody int64 = 512 * 1024
	DefaultTimeout       = 10 * time.Second
	HttpPrefix           = "http://"
	HttpsPrefix          = "https://"
	maxRedirects         = 5
)

// 静态 header 值，避免每次请求重新分配。
const (
	defaultAccept       = "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*"
	defaultPragma       = "no-cache"
	defaultCacheControl = "no-cache"
)

// OptionsRequest 请求配置参数。
type OptionsRequest struct {
	Proxy              string
	Timeout            time.Duration
	FollowRedirects    bool
	InsecureSkipVerify bool
	CustomHeaders      map[string]string
}

var (
	defaultHTTPClient     *HTTPClient
	defaultHTTPClientOnce sync.Once
)

// DefaultHTTPClient 返回进程级默认 HTTP 客户端（用于 CEL 反连等无 Runner 上下文的场景）。
func DefaultHTTPClient() *HTTPClient {
	defaultHTTPClientOnce.Do(func() {
		defaultHTTPClient = NewHTTPClient()
	})
	return defaultHTTPClient
}

// setDefaults 填充 OptionsRequest 的零值字段。
func setDefaults(options *OptionsRequest) {
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Second
	}
}

// configureHeaders 配置请求头信息。
func configureHeaders(req *retryablehttp.Request, options OptionsRequest) {
	req.Header.Set("User-Agent", common.RandomUA())
	req.Header.Set("Accept", defaultAccept)
	req.Header.Set("X-Forwarded-For", common.GetRandomIP())
	req.Header.Set("Pragma", defaultPragma)
	req.Header.Set("Cache-Control", defaultCacheControl)
	req.Header.Set("Cookie", "cookie="+common.RandomString(15))

	if req.Method == http.MethodPost && req.Header.Get("Content-Type") == "" {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	for key, value := range options.CustomHeaders {
		req.Header.Set(key, value)
	}
}

func clientCacheKey(proxy string, timeout time.Duration, followRedirects bool) string {
	redir := "0"
	if followRedirects {
		redir = "1"
	}
	return proxy + "|" + timeout.String() + "|" + redir
}

// createRedirectPolicy 创建重定向策略。
func createRedirectPolicy(followRedirects bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("达到最大重定向次数: %d", maxRedirects)
		}
		// 跨源重定向时剥离自定义请求头，避免把 API Token 等敏感头发往第三方。
		// Go 自身只剥离 Authorization/Cookie 等固定敏感头，不处理任意自定义头。
		if len(via) > 0 && !sameRedirectOrigin(via[0].URL, req.URL) {
			stripCrossOriginHeaders(req)
		}
		if len(via) > 0 {
			originalReq := via[len(via)-1]
			if originalReq.Body != nil && originalReq.Body != http.NoBody {
				if originalReq.GetBody == nil {
					if bodyBytes, err := io.ReadAll(originalReq.Body); err == nil {
						originalReq.GetBody = func() (io.ReadCloser, error) {
							return io.NopCloser(bytes.NewReader(bodyBytes)), nil
						}
						originalReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					}
				}
				if req.Body == nil || req.Body == http.NoBody {
					if originalReq.GetBody != nil {
						if newBody, err := originalReq.GetBody(); err == nil {
							req.Body = newBody
							if req.GetBody == nil {
								req.GetBody = originalReq.GetBody
							}
						}
					}
				} else if req.Body != nil && req.Body != http.NoBody {
					if req.GetBody == nil {
						if originalReq.GetBody != nil {
							req.GetBody = originalReq.GetBody
						} else {
							if bodyBytes, err := io.ReadAll(req.Body); err == nil {
								req.GetBody = func() (io.ReadCloser, error) {
									return io.NopCloser(bytes.NewReader(bodyBytes)), nil
								}
								req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
							}
						}
					}
				}
			} else {
				if req.GetBody == nil {
					req.GetBody = func() (io.ReadCloser, error) {
						return http.NoBody, nil
					}
				}
			}
		}
		return nil
	}
}

// redirectSafeHeaders 跨源重定向时允许保留的请求头（大小写规范化后比较）。
var redirectSafeHeaders = map[string]struct{}{
	"User-Agent":      {},
	"Accept":          {},
	"Accept-Language": {},
	"Accept-Encoding": {},
	"Referer":         {},
}

// sameRedirectOrigin 判断两个 URL 是否同源（scheme + host 相同）。
func sameRedirectOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// stripCrossOriginHeaders 删除不在安全白名单内的请求头，防止自定义头跨源泄漏。
func stripCrossOriginHeaders(req *http.Request) {
	for key := range req.Header {
		if _, ok := redirectSafeHeaders[http.CanonicalHeaderKey(key)]; !ok {
			req.Header.Del(key)
		}
	}
}

// Url2ProtoUrl 将 net/url.URL 转为 proto.UrlType。
func Url2ProtoUrl(u *url.URL) *proto.UrlType {
	return &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

// ParseRequest 解析 HTTP 请求为 proto.Request。
func ParseRequest(oReq *http.Request) (*proto.Request, error) {
	req := &proto.Request{
		Method: oReq.Method,
		Url:    common.Url2UrlType(oReq.URL),
	}

	header := make(map[string]string, len(oReq.Header))
	for k := range oReq.Header {
		header[k] = oReq.Header.Get(k)
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")

	if oReq.Body != nil && oReq.Body != http.NoBody {
		data, err := io.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	}

	return req, nil
}
