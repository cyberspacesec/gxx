/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: icon.go
    @Date: 2025/2/21 下午3:06*
*/
package finger

import (
	"context"
	"encoding/base64"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spaolacci/murmur3"
)

// GetIconHash 获取 icon hash。
type GetIconHash struct {
	iconURL string
	headers map[string]string
	proxy   string
	client  *network.HTTPClient
	timeout time.Duration
}

// NewGetIconHash 初始化 GetIconHash
func NewGetIconHash(iconURL string, proxy string) *GetIconHash {
	return &GetIconHash{
		iconURL: iconURL,
		headers: map[string]string{
			"User-Agent":      common.RandomUA(),
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
		},
		proxy:   proxy,
		timeout: defaultTimeout,
	}
}

// WithHTTPClient 绑定 Runner/Engine 持有的 HTTP 客户端（nil 时回退 DefaultHTTPClient）。
func (g *GetIconHash) WithHTTPClient(client *network.HTTPClient) *GetIconHash {
	g.client = client
	return g
}

// WithTimeout 设置 favicon 请求超时。
func (g *GetIconHash) WithTimeout(timeout time.Duration) *GetIconHash {
	if timeout > 0 {
		g.timeout = timeout
	}
	return g
}

func (g *GetIconHash) httpClient() *network.HTTPClient {
	if g.client != nil {
		return g.client
	}
	return network.DefaultHTTPClient()
}

// WithHeaders 复制页面请求头，支持需要认证或 Referer 的图标资源。
func (g *GetIconHash) WithHeaders(headers map[string]string) *GetIconHash {
	if len(headers) > 0 && g.headers == nil {
		g.headers = make(map[string]string, len(headers))
	}
	for key, value := range headers {
		g.headers[http.CanonicalHeaderKey(key)] = value
	}
	return g
}

// getIconHash 获取 icon 的 hash 值。
func (g *GetIconHash) getIconHash(ctx context.Context, iconURL string) int32 {
	if len(iconURL) >= 5 && strings.EqualFold(iconURL[:5], "data:") {
		return g.hashDataURL(iconURL)
	}
	return g.hashHTTPURL(ctx, iconURL)
}

// hashDataURL 处理 data URL 并计算 hash 值
func (g *GetIconHash) hashDataURL(iconURL string) int32 {
	header, payload, found := strings.Cut(iconURL, ",")
	if !found || len(header) < 5 || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(header[5:])), "image/") {
		return 0
	}
	if at := strings.IndexByte(payload, '#'); at >= 0 {
		payload = payload[:at]
	}
	reader := &iconDataReader{payload: payload, encoded: strings.HasSuffix(strings.ToLower(strings.TrimSpace(header)), ";base64")}
	var source io.Reader = reader
	if reader.encoded {
		source = base64.NewDecoder(base64.StdEncoding, reader)
	}
	hash, err := hashIconReader(source, nil)
	if err != nil {
		return 0
	}
	return hash
}

// hashHTTPURL 处理 HTTP URL 并计算 hash 值。
func (g *GetIconHash) hashHTTPURL(parentCtx context.Context, iconURL string) int32 {
	if iconContextExpired(parentCtx) {
		return 0
	}
	timeout := g.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	options := network.OptionsRequest{
		Proxy:              g.proxy,
		Timeout:            timeout,
		FollowRedirects:    true,
		InsecureSkipVerify: true,
		CustomHeaders:      g.headers,
	}
	reqCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	resp, err := g.httpClient().GetResource(reqCtx, iconURL, options)
	if err != nil {
		logger.FromContext(reqCtx).Debug("创建请求失败: %s", err)
		return 0
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0
	}
	imageMIME := strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type"))), "image/")
	probe := iconContentProbe{validate: true, imageMIME: imageMIME}
	hash, err := hashIconReader(resp.Body, &probe)
	if err != nil {
		logger.FromContext(reqCtx).Debug("读取图标失败: %s", err)
		return 0
	}
	if iconContextExpired(reqCtx) {
		return 0
	}
	probe.finish()
	if probe.binary || probe.elementIs("svg") || imageMIME && !probe.html() {
		return hash
	}
	return 0
}

// StandBase64 标准化Base64编码
func StandBase64(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte{}
	}
	encodedLen := base64.StdEncoding.EncodedLen(len(raw))
	result := make([]byte, encodedLen+encodedLen/76+1)
	n := encodeIconBase64(result, raw)
	result[n] = '\n'
	return result
}

// encodeIconBase64 每 57 个输入字节产生一行 76 字节的编码。
// 满行末尾保留换行；调用方另写最终换行，保持项目哈希约定的双换行边界。
func encodeIconBase64(dst, raw []byte) int {
	n := 0
	for len(raw) >= 57 {
		base64.StdEncoding.Encode(dst[n:n+76], raw[:57])
		dst[n+76] = '\n'
		n += 77
		raw = raw[57:]
	}
	if len(raw) > 0 {
		encodedLen := base64.StdEncoding.EncodedLen(len(raw))
		base64.StdEncoding.Encode(dst[n:n+encodedLen], raw)
		n += encodedLen
		// 55、56 字节的尾块补齐后同样占满一行。
		if encodedLen == 76 {
			dst[n] = '\n'
			n++
		}
	}
	return n
}

// hashIconBytes 用固定大小的暂存区逐块编码并计算哈希，避免保留完整编码副本。
func hashIconBytes(raw []byte) int32 {
	if len(raw) == 0 {
		return 0
	}
	h := murmur3.New32()
	var block [77*32 + 1]byte
	for len(raw) >= 57*32 {
		n := encodeIconBase64(block[:], raw[:57*32])
		_, _ = h.Write(block[:n])
		raw = raw[57*32:]
	}
	n := encodeIconBase64(block[:], raw)
	block[n] = '\n'
	_, _ = h.Write(block[:n+1])
	return int32(h.Sum32())
}

// Run 运行获取 icon hash 的流程。
func (g *GetIconHash) Run(ctx context.Context) string {
	if iconContextExpired(ctx) {
		return "0"
	}
	var hash int32
	if g.iconURL != "" {
		hash = g.getIconHash(ctx, g.iconURL)
	}
	if hash == 0 {
		defaultURL := defaultFaviconURL(g.iconURL)
		if defaultURL != "" {
			hash = g.getIconHash(ctx, defaultURL)
		}
	}
	return strconv.FormatInt(int64(hash), 10)
}

// context 的取消通知受调度影响，候选请求同时核对实际截止时间。
func iconContextExpired(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}
