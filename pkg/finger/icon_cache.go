package finger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cyberspacesec/gxx/pkg/network"
)

// normalizeIconURL 去除片段，保留路径、查询参数顺序与编码。
func normalizeIconURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// 缓存只描述实际抓取成功的地址，按实例、请求头和会话 Cookie 隔离。
func getIconHashExactCached(ctx context.Context, client *network.HTTPClient, iconURL, proxy string, timeout time.Duration, headers map[string]string) string {
	if iconURL == "" || iconContextExpired(ctx) {
		return ""
	}
	if len(iconURL) >= 5 && strings.EqualFold(iconURL[:5], "data:") {
		return strconv.FormatInt(int64((&GetIconHash{}).hashDataURL(iconURL)), 10)
	}
	if client == nil {
		client = network.DefaultHTTPClient()
	}
	cookies := client.ResourceCookies(iconURL, network.OptionsRequest{Proxy: proxy, Timeout: timeout, FollowRedirects: true})
	key := sha256.Sum256([]byte(normalizeIconURL(iconURL) + "\x1f" + proxy + "\x1f" + iconHeaderDigest(headers, cookies)))
	if hash, ok := client.ResourceHash(key); ok {
		return hash
	}
	hash := strconv.FormatInt(int64(NewGetIconHash(iconURL, proxy).WithHTTPClient(client).WithTimeout(timeout).WithHeaders(headers).getIconHash(ctx, iconURL)), 10)
	client.StoreResourceHash(key, hash)
	return hash
}

func iconHeaderDigest(headers map[string]string, cookies []*http.Cookie) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, key := range keys {
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(headers[key]))
		h.Write([]byte{0})
	}
	h.Write([]byte{0})
	for _, cookie := range cookies {
		h.Write([]byte(cookie.Name))
		h.Write([]byte{0})
		h.Write([]byte(cookie.Value))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
