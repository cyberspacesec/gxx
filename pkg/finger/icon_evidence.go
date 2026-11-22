package finger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/url"
	"strings"

	"github.com/cyberspacesec/gxx/pkg/network"
)

// IconEvidence 是页面图标的证据，来自计算图标哈希的同一次读取，不另发请求。
// Data 是图标原始字节，超过上限时为空并置 TooLarge；CrossOrigin 表示图标与页面不属于
// 同一资产（协议、主机、端口）。
type IconEvidence struct {
	URL         string
	ContentType string
	Bytes       int64
	SHA256      string
	MMH3        string
	Data        []byte
	TooLarge    bool
	CrossOrigin bool
}

// iconCapture 在图标哈希的读取过程中同步计算摘要并保留不超过 limit 的原始字节。
type iconCapture struct {
	reader   io.Reader
	hash     hash.Hash
	limit    int
	data     []byte
	bytes    int64
	tooLarge bool
}

func newIconCapture(reader io.Reader, limit int) *iconCapture {
	return &iconCapture{reader: reader, hash: sha256.New(), limit: limit}
}

func (c *iconCapture) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if n > 0 {
		c.hash.Write(p[:n])
		c.bytes += int64(n)
		if !c.tooLarge {
			if c.bytes > int64(c.limit) {
				c.tooLarge, c.data = true, nil
			} else {
				c.data = append(c.data, p[:n]...)
			}
		}
	}
	return n, err
}

// evidence 生成证据；hash 为图标的 MMH3 哈希文本。
func (c *iconCapture) evidence(iconURL, contentType, mmh3 string) *IconEvidence {
	return &IconEvidence{URL: iconURL, ContentType: contentType, Bytes: c.bytes, SHA256: hex.EncodeToString(c.hash.Sum(nil)), MMH3: mmh3, Data: c.data, TooLarge: c.tooLarge}
}

// size 是证据在缓存中占用的字节数。
func (e *IconEvidence) size() int {
	if e == nil {
		return 0
	}
	return len(e.Data) + len(e.URL) + len(e.ContentType) + 128
}

type iconEvidenceKey struct{}

// iconEvidenceSlot 接收页面图标的证据；只有入口跳转链的最后一页会设置它。
type iconEvidenceSlot struct{ evidence *IconEvidence }

// WithIconEvidenceSlot 让 ctx 下为页面计算图标时保存证据，返回读取证据的函数。
// 需要同时在请求选项中开启 IconEvidence。
func WithIconEvidenceSlot(ctx context.Context) (context.Context, func() *IconEvidence) {
	slot := &iconEvidenceSlot{}
	return context.WithValue(ctx, iconEvidenceKey{}, slot), func() *IconEvidence { return slot.evidence }
}

// keepIconEvidence 把选中图标的证据交给 ctx 中的接收者，补上是否跨源。
func keepIconEvidence(ctx context.Context, pageURL string, evidence *IconEvidence) {
	slot, _ := ctx.Value(iconEvidenceKey{}).(*iconEvidenceSlot)
	if slot == nil || evidence == nil {
		return
	}
	copied := *evidence
	if !strings.HasPrefix(strings.ToLower(copied.URL), "data:") {
		page, pageErr := url.Parse(pageURL)
		icon, iconErr := url.Parse(copied.URL)
		copied.CrossOrigin = pageErr != nil || iconErr != nil || !network.SameOrigin(page, icon)
	}
	slot.evidence = &copied
}

// dataURLEvidenceURL 只保留 data URL 的媒体类型部分，载荷已在 Data 中。
func dataURLEvidenceURL(iconURL string) string {
	if header, _, found := strings.Cut(iconURL, ","); found {
		return header + ","
	}
	return iconURL
}
