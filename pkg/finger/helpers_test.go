package finger

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"

	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/spaolacci/murmur3"
)

// 测试辅助：把常见的调用形式包装到生产函数上，测试覆盖的是扫描实际执行的代码。

// GetTitle 读取响应正文并提取标题。
func GetTitle(urlStr string, resp *http.Response) string {
	body, err := network.ReadResponseBody(resp, network.MaxDefaultBody)
	_ = resp.Body.Close()
	if err != nil {
		return ""
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	return GetTitleFromBody(ctx, urlStr, resp, body, network.DefaultHTTPClient(), network.OptionsRequest{Timeout: network.DefaultTimeout, FollowRedirects: true})
}

// GetIconURL 返回优先级最高的图标地址，没有候选时为默认的 /favicon.ico。
func GetIconURL(pageURL, body string) string { return GetIconURLFromBody(pageURL, []byte(body)) }

func GetIconURLFromBody(pageURL string, body []byte) string {
	if urls := extractIconURLs(pageURL, body); len(urls) > 0 {
		return urls[0]
	}
	return defaultFaviconURL(pageURL)
}

func extractIconURLs[S metadataSource](pageURL string, body S) []string {
	urls, _ := collectIconURLs(pageURL, body)
	return urls
}

func ExtractICPRecord(body string) string { return ExtractICPRecordFromBody([]byte(body)) }

// StandBase64 是图标哈希约定的参考实现：每 76 个字符换行，结尾再加一个换行。
func StandBase64(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte{}
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	var out bytes.Buffer
	for len(encoded) > 76 {
		out.WriteString(encoded[:76])
		out.WriteByte('\n')
		encoded = encoded[76:]
	}
	out.WriteString(encoded)
	if len(encoded) == 76 {
		out.WriteByte('\n')
	}
	out.WriteByte('\n')
	return out.Bytes()
}

// hashIconBytes 用参考实现计算整段图片的哈希，与流式实现对照。
func hashIconBytes(raw []byte) int32 {
	if len(raw) == 0 {
		return 0
	}
	h := murmur3.New32()
	_, _ = h.Write(StandBase64(raw))
	return int32(h.Sum32())
}

// iconHashOf 下载并计算单个图标地址的哈希。
func iconHashOf(g *GetIconHash) string {
	return strconv.FormatInt(int64(g.getIconHash(context.Background(), g.iconURL)), 10)
}
