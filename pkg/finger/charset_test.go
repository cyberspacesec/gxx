package finger

import (
	"strings"
	"testing"
)

// decodeHTMLBody 必须按声明的字符集解码，不能再把所有非 UTF-8 正文一律当作 GB18030。
func TestDecodeHTMLBodyHonorsDeclaredCharset(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        []byte
		wantSub     string
	}{
		// Big5："測試"（U+6E2C U+8A66）
		{"Big5", "text/html; charset=big5", []byte{0xB4, 0xFA, 0xB8, 0xD5}, "測試"},
		// Shift_JIS："テスト"
		{"Shift_JIS", "text/html; charset=shift_jis", []byte{0x83, 0x65, 0x83, 0x58, 0x83, 0x67}, "テスト"},
		// ISO-8859-1（WHATWG 映射到 windows-1252）："Café"
		{"ISO-8859-1", "text/html; charset=iso-8859-1", []byte{0x43, 0x61, 0x66, 0xE9}, "Café"},
		// GBK："你好"
		{"GBK", "text/html; charset=gbk", []byte{0xC4, 0xE3, 0xBA, 0xC3}, "你好"},
		// GB18030 标签
		{"GB18030", "text/html; charset=gb18030", []byte{0xC4, 0xE3, 0xBA, 0xC3}, "你好"},
		// UTF-8 原样保留
		{"UTF-8", "text/html; charset=utf-8", []byte("统一身份认证"), "统一身份认证"},
		// 无字符集标签但合法 UTF-8：原样保留
		{"无标签合法UTF-8", "", []byte("hello 世界"), "hello 世界"},
		// 无字符集标签、非法 UTF-8：GB18030 兜底（面向省略标注的中文站点）
		{"无标签GBK兜底", "text/plain", []byte{0xC4, 0xE3, 0xBA, 0xC3}, "你好"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(decodeHTMLBody(tc.body, tc.contentType))
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("解码结果 %q 不含期望子串 %q", got, tc.wantSub)
			}
		})
	}
}

// 正文内 <meta charset> 声明也应被识别（无 Content-Type 头时）。
func TestDecodeHTMLBodyHonorsMetaCharset(t *testing.T) {
	// <meta charset="big5"> + Big5 编码的"測試"
	body := append([]byte(`<html><head><meta charset="big5"></head><body>`), 0xB4, 0xFA, 0xB8, 0xD5)
	body = append(body, []byte(`</body></html>`)...)
	got := string(decodeHTMLBody(body, ""))
	if !strings.Contains(got, "測試") {
		t.Fatalf("meta charset 未生效: %q", got)
	}
}

// 空正文与极短正文不应 panic。
func TestDecodeHTMLBodyEdgeCases(t *testing.T) {
	if got := decodeHTMLBody(nil, "text/html; charset=big5"); len(got) != 0 {
		t.Fatalf("空正文应返回空: %q", got)
	}
	_ = decodeHTMLBody([]byte{0x00}, "")
	_ = decodeHTMLBody([]byte("a"), "text/html; charset=unknown-xyz")
}
