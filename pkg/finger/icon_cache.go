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
// evidence 不小于 0 时同时返回证据（原始字节最多 evidence 字节），证据与哈希一起缓存，
// 命中缓存时不再请求；记录证据的条目与不记录证据的条目分开缓存。
func getIconHashExactCached(ctx context.Context, client *network.HTTPClient, iconURL, proxy string, timeout time.Duration, headers map[string]string, evidence int) (string, *IconEvidence) {
	if iconURL == "" || iconContextExpired(ctx) {
		return "", nil
	}
	if len(iconURL) >= 5 && strings.EqualFold(iconURL[:5], "data:") {
		g := &GetIconHash{evidenceLimit: evidence}
		return strconv.FormatInt(int64(g.hashDataURL(iconURL)), 10), g.evidence
	}
	if client == nil {
		client = network.DefaultHTTPClient()
	}
	cookies := client.ResourceCookies(ctx, iconURL)
	material := normalizeIconURL(iconURL) + "\x1f" + proxy + "\x1f" + iconHeaderDigest(headers, cookies)
	if evidence >= 0 {
		material += "\x1fevidence:" + strconv.Itoa(evidence)
	}
	key := sha256.Sum256([]byte(material))
	if record, ok := client.Resource(key); ok {
		captured, _ := record.Evidence.(*IconEvidence)
		return record.Hash, captured
	}
	g := NewGetIconHash(iconURL, proxy).WithHTTPClient(client).WithTimeout(timeout).WithHeaders(headers)
	if evidence >= 0 {
		g.WithEvidence(evidence)
	}
	hash := strconv.FormatInt(int64(g.getIconHash(ctx, iconURL)), 10)
	client.StoreResource(key, network.ResourceRecord{Hash: hash, Evidence: g.evidence, Size: g.evidence.size()})
	return hash, g.evidence
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
