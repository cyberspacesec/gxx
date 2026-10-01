package finger

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/utils/common"
)

// 参考历史编码定义，独立验证补齐、行宽以及最终换行。
func legacyIconBase64(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte{}
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	var out bytes.Buffer
	for i := range encoded {
		out.WriteByte(encoded[i])
		if (i+1)%76 == 0 {
			out.WriteByte('\n')
		}
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func TestIconEncodingAndHashParity(t *testing.T) {
	rng := rand.New(rand.NewPCG(17, 29))
	data := make([]byte, network.MaxDefaultBody)
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	lengths := make([]int, 4097)
	for i := range lengths {
		lengths[i] = i
	}
	lengths = append(lengths, 8191, 8192, 16384, 65535, 65536, len(data))
	for _, size := range lengths {
		raw := data[:size]
		want := legacyIconBase64(raw)
		if got := StandBase64(raw); !bytes.Equal(got, want) {
			t.Fatalf("编码内容变化: size=%d", size)
		}
		if got := hashIconBytes(raw); got != common.Mmh3Hash32(want) {
			t.Fatalf("图标哈希变化: size=%d hash=%d", size, got)
		}
	}
}

func TestIconFallbackPreservesTransientResponses(t *testing.T) {
	data := []byte("fixed image bytes")
	want := strconv.FormatInt(int64(common.Mmh3Hash32(legacyIconBase64(data))), 10)
	for _, firstStatus := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(firstStatus), func(t *testing.T) {
			var calls atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(firstStatus)
					return
				}
				w.Header().Set("Content-Type", "image/png")
				_, _ = w.Write(data)
			}))
			defer s.Close()
			client := network.NewHTTPClient()
			defer client.Close()
			got := NewGetIconHash(s.URL+"/favicon.ico", "").WithHTTPClient(client).Run(context.Background())
			if got != want || calls.Load() != 2 {
				t.Fatalf("相同地址的后备请求行为变化: got=%s want=%s calls=%d", got, want, calls.Load())
			}
		})
	}
}

func TestTitleSourcesPreserveContent(t *testing.T) {
	client := network.NewHTTPClient()
	defer client.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"top.login.title": "国际化标题",}`)
	}))
	defer s.Close()
	for _, tc := range []struct{ name, body, contentType, want string }{
		{"HTML", "<TITLE>  中文\t\r\n 标题  </TITLE>", "text/html; charset=utf-8", "中文 标题"},
		{"DOM", "<title>" + strings.Repeat("x", 80) + `</title><script>document.title = ("动态标题")</script>`, "text/html", "动态标题"},
		{"i18n", `<title>静态标题</title><script type="text/javascript" src="/assets/i18n/messages.js"></script>`, "text/html", "国际化标题"},
		{"多个脚本", `<title>静态标题</title><script type="text/javascript" src=""></script><script type="text/javascript" src="/ordinary.js"></script><script type="text/javascript" src="/i18n/data.txt"></script><script TYPE="text/javascript" src="/assets/i18n/messages.js"></script><script type="text/javascript" src="/later/i18n/messages.js"></script>`, "text/html", "国际化标题"},
		{"GB18030", "<title>\xc4\xe3\xba\xc3</title>", "text/html; charset=gb18030", "你好"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Content-Type": {tc.contentType}}}
			got := GetTitleFromBody(context.Background(), s.URL, resp, []byte(tc.body), client, network.OptionsRequest{Timeout: network.DefaultTimeout})
			if got != tc.want {
				t.Fatalf("标题变化: got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestICPExtractionBoundaries(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"<html>没有备案信息</html>", ""},
		{`<a href="https://beian.miit.gov.cn/">京ICP备12345678号</a>`, "京ICP备12345678号"},
		{"<div>备案号：京iCp备12345678号</div>", "京iCp备12345678号"},
		{"<html>\xbe\xa9ICP\xb1\xb8" + "12345678" + "\xba\xc5</html>", "京ICP备12345678号"},
		{"京ICP备12345678号", "京ICP备12345678号"},
		{`<a href="https://beian.miit.gov.cn/">其他登记号</a>`, ""},
		{`<a href="https://beian.miit.gov.cn/">京ICP备12345678号.js</a>`, ""},
	} {
		if got := ExtractICPRecord(tc.body); got != tc.want {
			t.Fatalf("备案号变化: body=%q got=%q want=%q", tc.body, got, tc.want)
		}
		if got := ExtractICPRecordFromBody([]byte(tc.body)); got != tc.want {
			t.Fatalf("字节正文备案号变化: body=%q got=%q want=%q", tc.body, got, tc.want)
		}
	}
}

func TestMetadataFieldsReleaseLargePages(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}}}
	// 先建立正则工作区，内存断言只关注长期持有字段的正文引用。
	GetTitleFromBody(context.Background(), "http://example.com/", resp, []byte("<title>warmup</title>"), nil, network.OptionsRequest{})
	ExtractICPRecord("<p>京ICP备12345678号</p>")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fields := make([]string, 96)
	for i := 0; i < len(fields); i += 3 {
		body := "<title>短标题</title><link rel='icon' href='/favicon.ico'><p>京ICP备12345678号</p>" + strings.Repeat("x", 512<<10)
		fields[i] = GetTitleFromBody(context.Background(), "http://example.com/", resp, []byte(body), nil, network.OptionsRequest{})
		fields[i+1] = ExtractICPRecord(body)
		fields[i+2] = GetIconURL("https://example.com/", body)
		if fields[i] != "短标题" || fields[i+1] != "京ICP备12345678号" || fields[i+2] != "https://example.com/favicon.ico" {
			t.Fatal("字段内容变化")
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(fields)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("96 个短字段的存活堆增量: %d 字节", retained)
	if retained > 4<<20 {
		t.Fatalf("短字段保留了大页正文: retained=%d", retained)
	}
}

func BenchmarkIconHash(b *testing.B) {
	for _, size := range []int{1024, 65536, int(network.MaxDefaultBody)} {
		data := bytes.Repeat([]byte("x"), size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				hashIconBytes(data)
			}
		})
	}
}

func BenchmarkICPWithoutRecord(b *testing.B) {
	body := strings.Repeat(`<div><span>普通正文</span></div>`, 8000)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractICPRecord(body)
	}
}

func BenchmarkServerVersion(b *testing.B) {
	header := http.Header{"Server": {"nginx/1.26.0 (Unix)"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ExtractServerInfo(header)
	}
}

func BenchmarkTitleExtraction(b *testing.B) {
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}}}
	for _, size := range []int{256, 256 << 10} {
		data := []byte("<title>短标题</title>" + strings.Repeat("x", size))
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				GetTitleFromBody(context.Background(), "http://example.com/", resp, data, nil, network.OptionsRequest{})
			}
		})
	}
}
