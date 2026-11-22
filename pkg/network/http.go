/*
Package network 提供 HTTP 请求、协议探测与请求解析工具。
*/
package network

import (
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/proto"
	"net/http"
	"net/url"
	"sync"
	"time"
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
	// Probe 表示这是确定目标是否为 HTTP 服务的入口请求：失败就是失败，不做兼容性回退。
	Probe bool
	// BodyLimit 是响应正文的读取上限（字节），0 表示 MaxDefaultBody。
	BodyLimit int64
}

// ReadLimit 返回响应正文的读取上限。
func (o OptionsRequest) ReadLimit() int64 {
	if o.BodyLimit > 0 {
		return o.BodyLimit
	}
	return MaxDefaultBody
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
func configureHeaders(req *http.Request, options OptionsRequest) {
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

// KeepPortableHeaders 只保留可以发给任何主机的通用请求头，删除其余全部请求头。
// 请求因重定向离开原来的源时使用：自定义请求头可能带有令牌或内网信息。
func KeepPortableHeaders(header http.Header) {
	for key := range header {
		switch http.CanonicalHeaderKey(key) {
		case "User-Agent", "Accept", "Accept-Language", "Referer":
		default:
			header.Del(key)
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
