package finger

import (
	"regexp"
	"strings"

	"github.com/cyberspacesec/gxx/utils/common"
	"golang.org/x/text/encoding/htmlindex"
)

var (
	// 从 Content-Type 头提取 charset。
	contentTypeCharsetRe = regexp.MustCompile(`(?i)charset\s*=\s*["']?([\w.:+-]+)`)
	// 从正文内的 <meta> 声明提取 charset（覆盖 <meta charset=...> 与 http-equiv 两种写法）。
	metaCharsetRe = regexp.MustCompile(`(?i)<meta[^>]+charset\s*=\s*["']?([\w.:+-]+)`)
)

// decodeHTMLBody 将响应正文解码为 UTF-8。
//
// 仅在存在明确字符集声明（Content-Type 头或正文前部的 <meta charset>）且该字符集
// 非 UTF-8 时，用对应解码器转换，修复此前把 Big5 / Shift_JIS / ISO-8859-1 等页面
// 统一按 GB18030 解码造成的乱码与关键字漏匹配。
//
// 无明确声明时不做字符集猜测（避免把中文 GBK 页面误判为 windows-1252）：
// 合法（含末尾被截断的多字节序列）UTF-8 原样保留，其余按 GB18030 兜底——
// 面向大量省略或错误标注字符集的中文站点。
//
// 返回值可能与入参共享底层数组（当无需转换时），调用方不得假设其独占。
func decodeHTMLBody(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return body
	}
	if name := explicitCharset(contentType, body); name != "" && name != "utf-8" && name != "utf8" {
		if enc, err := htmlindex.Get(name); err == nil {
			if decoded, derr := enc.NewDecoder().Bytes(body); derr == nil && len(decoded) > 0 {
				return decoded
			}
		}
	}
	if common.ValidUTF8Truncated(body) {
		return body
	}
	return []byte(common.Str2UTF8(string(body)))
}

// explicitCharset 返回响应明确声明的字符集名称（小写），不存在时返回空字符串。
// 优先 Content-Type 头，其次扫描正文前 1024 字节内的 <meta> 声明。
func explicitCharset(contentType string, body []byte) string {
	if m := contentTypeCharsetRe.FindStringSubmatch(contentType); len(m) >= 2 {
		return strings.ToLower(m[1])
	}
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	if m := metaCharsetRe.FindSubmatch(head); len(m) >= 2 {
		return strings.ToLower(string(m[1]))
	}
	return ""
}
