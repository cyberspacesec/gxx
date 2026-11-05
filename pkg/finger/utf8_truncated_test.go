package finger

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/common"
)

// 正文读取上限会把页面截在任意字节处。末尾被截断的 UTF-8 页面仍然是 UTF-8，
// 不能因为最后半个字符就把整页按 GB18030 重新解码。
func truncatedChinesePage() (full, truncated []byte) {
	full = []byte(`<html><head><meta charset="utf-8"><title>统一身份认证平台</title></head><body>` + strings.Repeat("<p>欢迎使用统一身份认证平台</p>", 500) + `</body></html>`)
	cut := bytes.LastIndex(full, []byte("证"))
	// "证" 占 3 字节，只保留前 2 个字节，模拟读取上限正好落在字符中间。
	return full, bytes.Clone(full[:cut+2])
}

func testResponse() *http.Response {
	// 非根路径 + 不可解析域名：避免 buildProtoResponsePage 对根路径 HTML 触发真实 favicon 抓取。
	u, _ := url.Parse("http://example.invalid/app")
	return &http.Response{
		StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1",
		Header:  http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Request: &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}},
	}
}

func TestTruncatedUTF8BodyIsNotReDecodedAsGB18030(t *testing.T) {
	_, truncated := truncatedChinesePage()
	if common.Str2UTF8(string(truncated)) != string(truncated) {
		t.Fatal("Str2UTF8 把末尾被截断的 UTF-8 文本当作 GB18030 转换")
	}
	for name, build := range map[string]func([]byte) []byte{
		"BuildProtoResponseOwned": func(b []byte) []byte {
			return BuildProtoResponseOwned(context.Background(), testResponse(), b, 0, network.NewHTTPClient(), network.OptionsRequest{}).Body
		},
		"BuildBaseProtoResponseOwned": func(b []byte) []byte {
			return BuildBaseProtoResponseOwned(context.Background(), testResponse(), b, 0, network.NewHTTPClient(), network.OptionsRequest{}, "").Body
		},
	} {
		got := build(bytes.Clone(truncated))
		if !bytes.Equal(got, truncated) {
			t.Fatalf("%s 改写了正文: 长度 %d -> %d", name, len(truncated), len(got))
		}
		if !bytes.Contains(got, []byte("统一身份认证平台")) {
			t.Fatalf("%s 之后丢失了中文关键字", name)
		}
	}
}

func TestTruncatedUTF8PageStillYieldsTitleAndICP(t *testing.T) {
	_, truncated := truncatedChinesePage()
	body := append([]byte(nil), truncated...)
	title := GetTitleFromBody(context.Background(), "http://example.invalid/app", testResponse(), body, network.NewHTTPClient(), network.OptionsRequest{Timeout: network.DefaultTimeout})
	if title != "统一身份认证平台" {
		t.Fatalf("标题=%q", title)
	}
	page := append([]byte(`<html><body><footer>京ICP备12345678号-1</footer>`+strings.Repeat("统一身份认证平台", 3000)), 0xe8, 0xaf) // 末尾半个"证"
	if got := ExtractICPRecordFromBody(page); got != "京ICP备12345678号-1" {
		t.Fatalf("备案号=%q", got)
	}
}

// 真正的 GB18030 页面必须继续被转换，不能因为放宽截断判断而漏掉。
func TestGB18030BodyIsStillConverted(t *testing.T) {
	gbk := []byte{0xc4, 0xe3, 0xba, 0xc3, 0xca, 0xc0, 0xbd, 0xe7} // "你好世界"
	body := append([]byte("<html><body>"), gbk...)
	body = append(body, []byte("</body></html>")...)
	got := BuildProtoResponseOwned(context.Background(), testResponse(), bytes.Clone(body), 0, network.NewHTTPClient(), network.OptionsRequest{})
	if !bytes.Contains(got.Body, []byte("你好世界")) {
		t.Fatalf("GB18030 正文未转换: %x", got.Body)
	}
	// 末尾恰好是 GB18030 的前导字节时，其余部分含有非法 UTF-8，仍应整体转换。
	tail := append(append([]byte(nil), body...), 0xc4)
	got = BuildProtoResponseOwned(context.Background(), testResponse(), tail, 0, network.NewHTTPClient(), network.OptionsRequest{})
	if !bytes.Contains(got.Body, []byte("你好世界")) {
		t.Fatalf("含截断尾部的 GB18030 正文未转换: %x", got.Body)
	}
}
