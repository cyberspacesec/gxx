package finger

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	nethtml "golang.org/x/net/html"
)

func expectedIconHash(data []byte) string {
	return strconv.FormatInt(int64(common.Mmh3Hash32(legacyIconBase64(data))), 10)
}

func TestDataIconUsesDecodedImageBytes(t *testing.T) {
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><text>a,b+c</text></svg>`)
	for _, tc := range []struct {
		uri  string
		data []byte
	}{
		{"data:image/png;base64,YWJj", []byte("abc")},
		{"data:image/png;base64,Y W\tJ\nj", []byte("abc")},
		{"data:image/png;base64,YWJj#fragment", []byte("abc")},
		{"DATA:image/png;BASE64,YWJj", []byte("abc")},
		{"data:image/png;base64,YWI", []byte("ab")},
		{"data:image/png;base64,%2B%2F8%3D", []byte{0xfb, 0xff}},
		{"data:image/svg+xml," + url.PathEscape(string(svg)), svg},
		{"data:image/svg+xml," + string(svg), svg},
	} {
		if got := (&GetIconHash{}).hashDataURL(tc.uri); strconv.FormatInt(int64(got), 10) != expectedIconHash(tc.data) {
			t.Fatalf("内联图标哈希不匹配: uri=%q hash=%d", tc.uri, got)
		}
	}
	for _, uri := range []string{"data:image/png;base64,?", "data:image/png;base64,a,b", "data:image/png;base64,", "data:image/png", "data:text/html;base64,YWJj", "data:image/png,%ZZ"} {
		if got := (&GetIconHash{}).hashDataURL(uri); got != 0 {
			t.Fatalf("非法的内联图标产生哈希: %d", got)
		}
	}
}

func TestIconMIMEAndSignatures(t *testing.T) {
	for _, tc := range []struct {
		name, ct string
		data     []byte
		valid    bool
	}{
		{"大小写MIME", "IMAGE/PNG; charset=binary", []byte("opaque image bytes"), true},
		{"PNG", "application/octet-stream", []byte("\x89PNG\r\n\x1a\nimage"), true},
		{"ICO", "text/plain", []byte("\x00\x00\x01\x00image"), true},
		{"JPEG", "text/plain", []byte("\xff\xd8\xff\xdbimage"), true},
		{"GIF", "text/plain", []byte("GIF89aimage"), true},
		{"WebP", "text/plain", []byte("RIFF1234WEBPimage"), true},
		{"SVG", "application/xml", []byte("\xef\xbb\xbf \n<?xml version='1.0'?><!-- comment --><SVG xmlns='http://www.w3.org/2000/svg'></SVG>"), true},
		{"XML不是图标", "application/xml", []byte("<?xml version='1.0'?><error/>"), false},
		{"HTML错误页", "image/png", []byte("<!DOCTYPE html><html><body>error</body></html>"), false},
		{"短签名", "text/plain", []byte("\x89PNG"), false},
		{"空正文", "image/png", nil, false},
		{"上限内正文", "image/png", bytes.Repeat([]byte("x"), int(network.MaxDefaultBody)), true},
		{"大图标正文", "image/png", bytes.Repeat([]byte("x"), 4<<20), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type", tc.ct); w.Write(tc.data) }))
			defer s.Close()
			client := network.NewHTTPClient()
			defer client.Close()
			got := NewGetIconHash(s.URL, "").WithHTTPClient(client).hashHTTPURL(context.Background(), s.URL)
			want := int32(0)
			if tc.valid {
				want = common.Mmh3Hash32(legacyIconBase64(tc.data))
			}
			if got != want {
				t.Fatalf("图片识别不匹配: got=%d want=%d", got, want)
			}
		})
	}
}

func TestPageIconCandidatesAndExactCache(t *testing.T) {
	first, second := []byte("first image"), []byte("second image")
	var recovered atomic.Bool
	var mu sync.Mutex
	calls := map[string]int{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.RequestURI()]++
		mu.Unlock()
		if r.URL.Query().Get("v") == "a" && !recovered.Load() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		if r.URL.Query().Get("v") == "a" {
			w.Write(first)
		} else {
			w.Write(second)
		}
	}))
	defer s.Close()
	client := network.NewHTTPClient()
	defer client.Close()
	body := []byte(`<link rel='icon' href='/icon.ico?v=a'><link rel='icon' href='/icon.ico?v=b'>`)
	if got := GetPageIconHash(context.Background(), client, s.URL, body, network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash(second) {
		t.Fatalf("候选回退失败: %s", got)
	}
	if got := GetPageIconHash(context.Background(), client, s.URL, body, network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash(second) {
		t.Fatalf("正缓存复用失败: %s", got)
	}
	recovered.Store(true)
	if got := GetPageIconHash(context.Background(), client, s.URL, body, network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash(first) {
		t.Fatalf("失败候选被后备内容污染缓存: %s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["/icon.ico?v=a"] != 3 || calls["/icon.ico?v=b"] != 1 || len(calls) != 2 {
		t.Fatalf("请求与缓存边界错误: %v", calls)
	}
}

func TestPageIconDefaultFallback(t *testing.T) {
	for _, body := range []string{"<title>页面</title>", `<link rel='icon' href='/missing.ico'>`, `<link rel='icon' href='data:image/png;base64,?'>`} {
		t.Run(body, func(t *testing.T) {
			var calls atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/favicon.ico" {
					http.NotFound(w, r)
					return
				}
				if calls.Add(1) == 1 && body == "<title>页面</title>" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "image/png")
				fmt.Fprint(w, "default image")
			}))
			defer s.Close()
			c := network.NewHTTPClient()
			defer c.Close()
			if got := GetPageIconHash(context.Background(), c, s.URL+"/app/login.html", []byte(body), network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash([]byte("default image")) {
				t.Fatalf("默认图标失败: %s", got)
			}
			wantCalls := int64(1)
			if body == "<title>页面</title>" {
				wantCalls = 2
			}
			if calls.Load() != wantCalls {
				t.Fatalf("默认重试次数: %d", calls.Load())
			}
		})
	}
}

func TestDefaultFaviconPrecedesSocialImage(t *testing.T) {
	var photos atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		if r.URL.Path == "/photo.png" {
			photos.Add(1)
			fmt.Fprint(w, "photo")
		} else {
			fmt.Fprint(w, "favicon")
		}
	}))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	if got := GetPageIconHash(context.Background(), c, s.URL, []byte(`<meta property='og:image' content='/photo.png'>`), network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash([]byte("favicon")) || photos.Load() != 0 {
		t.Fatalf("社交照片替代了站点图标: hash=%s photos=%d", got, photos.Load())
	}
}

func TestSocialImageFallbackAfterMissingDefault(t *testing.T) {
	var defaults atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			defaults.Add(1)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "photo")
	}))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	if got := GetPageIconHash(context.Background(), c, s.URL, []byte(`<meta property='og:image' content='/photo.png'>`), network.OptionsRequest{Timeout: time.Second}); got != expectedIconHash([]byte("photo")) || defaults.Load() != 2 {
		t.Fatalf("图片线索后备失效: hash=%s defaults=%d", got, defaults.Load())
	}
}

func TestPageIconCancellationAndBudget(t *testing.T) {
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); <-r.Context().Done() }))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	body := []byte(`<link rel='icon' href='/first.ico'><link rel='icon' href='/second.ico'>`)
	start := time.Now()
	got := GetPageIconHash(context.Background(), c, s.URL, body, network.OptionsRequest{Timeout: 60 * time.Millisecond})
	if got != "0" || time.Since(start) > 500*time.Millisecond || calls.Load() != 1 {
		t.Fatalf("候选没有共享取消预算: got=%s calls=%d duration=%v", got, calls.Load(), time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	GetPageIconHash(ctx, c, s.URL, body, network.OptionsRequest{Timeout: time.Second})
	if calls.Load() != 1 {
		t.Fatal("取消后仍产生网络请求")
	}
}

type iconDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c iconDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestIconExpiredDeadlineBeforeCancellationNotification(t *testing.T) {
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "image")
	}))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	body := []byte(`<link rel="icon" href="/image.png">`)
	options := network.OptionsRequest{Timeout: time.Second}
	if got := GetPageIconHash(context.Background(), c, s.URL, body, options); got != expectedIconHash([]byte("image")) {
		t.Fatalf("缓存预热失败：%s", got)
	}
	// 模拟截止时间已到、取消 goroutine 尚未运行的窗口。
	ctx := iconDeadlineContext{context.Background(), time.Now().Add(-time.Second)}
	if ctx.Err() != nil {
		t.Fatal("测试上下文不应发送取消通知")
	}
	if got := GetPageIconHash(ctx, c, s.URL, body, options); got != "0" || calls.Load() != 1 {
		t.Fatalf("截止后仍返回缓存或发送请求：hash=%s calls=%d", got, calls.Load())
	}
	inline := `<link rel="icon" href="data:image/png;base64,YWJj">`
	if got := GetPageIconHash(ctx, c, s.URL, []byte(inline), options); got != "0" {
		t.Fatalf("截止后仍计算内联图标：%s", got)
	}
	if got := NewGetIconHash("data:image/png;base64,YWJj", "").Run(ctx); got != "0" {
		t.Fatalf("截止后独立图标仍返回结果：%s", got)
	}
}

func TestIconKeepAlive(t *testing.T) {
	var conns atomic.Int64
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") == "close" {
			t.Error("图标请求关闭连接")
		}
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "image")
	}))
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	s.Start()
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	g := NewGetIconHash(s.URL, "").WithHTTPClient(c)
	for _, path := range []string{"/a.ico", "/b.ico", "/c.ico"} {
		if g.hashHTTPURL(context.Background(), s.URL+path) == 0 {
			t.Fatal("图标请求失败")
		}
	}
	if conns.Load() != 1 {
		t.Fatalf("连接未复用: %d", conns.Load())
	}
}

func TestIconCandidateLimitsAndQueryDeduplication(t *testing.T) {
	body := `<link rel='icon' href='/same.ico?v=a#x'><link rel='icon' href='/same.ico?v=a#y'><link rel='icon' href='/same.ico?v=b'>`
	urls := extractIconURLs("https://example.com/", body)
	if len(urls) != 2 || urls[0] == urls[1] {
		t.Fatalf("去重损坏查询参数: %v", urls)
	}
	var markup strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&markup, `<link rel='icon' href='/icon-%d.png'>`, i)
	}
	body = markup.String()
	if urls := extractIconURLs("https://example.com/", body); len(urls) != maxIconCandidates {
		t.Fatalf("候选容量: %d", len(urls))
	}
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.NotFound(w, r) }))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	if got := GetPageIconHash(context.Background(), c, s.URL, []byte(body), network.OptionsRequest{Timeout: time.Second}); got != "0" || calls.Load() != maxIconAttempts+1 {
		t.Fatalf("抓取没有上限: hash=%s calls=%d", got, calls.Load())
	}
}

func TestConcurrentMetadataBorrowedBody(t *testing.T) {
	body := []byte(`<LINK HREF='/favicon.ico' REL='icon'><a href='https://beian.miit.gov.cn/'>京ICP<span>备12345678</span>号-2</a>`)
	original := bytes.Clone(body)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if GetIconURLFromBody("https://example.com/", body) != "https://example.com/favicon.ico" || ExtractICPRecordFromBody(body) != "京ICP备12345678号-2" {
					t.Error("并发解析结果变化")
					return
				}
			}
		}()
	}
	wg.Wait()
	if !bytes.Equal(body, original) {
		t.Fatal("解析修改了共享正文")
	}
}

func TestIconAuthenticatedHeadersAndCookies(t *testing.T) {
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: r.URL.Query().Get("id"), Path: "/"})
			fmt.Fprint(w, "session")
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "image/png")
		cookie, _ := r.Cookie("session")
		session := ""
		if cookie != nil {
			session = cookie.Value
		}
		fmt.Fprint(w, r.Header.Get("Authorization")+":"+session)
	}))
	defer s.Close()
	c := network.NewHTTPClient()
	defer c.Close()
	body := []byte(`<link rel='icon' href='/protected.ico'>`)
	for _, auth := range []string{"alice", "bob", "alice"} {
		got := GetPageIconHash(context.Background(), c, s.URL, body, network.OptionsRequest{Timeout: time.Second, CustomHeaders: map[string]string{"Authorization": auth}})
		if got != expectedIconHash([]byte(auth+":")) {
			t.Fatalf("认证上下文串用缓存: auth=%s hash=%s", auth, got)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("认证上下文缓存次数: %d", calls.Load())
	}
	for _, session := range []string{"first", "second", "first"} {
		resp, err := c.GetResource(context.Background(), s.URL+"/session?id="+session, network.OptionsRequest{Timeout: time.Second, FollowRedirects: true})
		if err != nil {
			t.Fatal(err)
		}
		network.ReadResponseBody(resp, 1024)
		resp.Body.Close()
		got := GetPageIconHash(context.Background(), c, s.URL, body, network.OptionsRequest{Timeout: time.Second})
		if got != expectedIconHash([]byte(":"+session)) {
			t.Fatalf("会话 Cookie 串用缓存: session=%s hash=%s", session, got)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("会话上下文缓存次数: %d", calls.Load())
	}
}

func TestIconCrossOriginCredentials(t *testing.T) {
	var origin string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Private-Token") != "" || strings.Contains(r.Header.Get("Cookie"), "private") {
			t.Error("跨源资源携带入口认证信息")
		}
		if r.Header.Get("Referer") != origin+"/" {
			t.Errorf("跨源 Referer 未限制为源地址: %q", r.Header.Get("Referer"))
		}
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "public image")
	}))
	defer other.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/real.png", http.StatusFound)
	}))
	defer s.Close()
	origin = s.URL
	c := network.NewHTTPClient()
	defer c.Close()
	headers := map[string]string{"Authorization": "private", "X-Private-Token": "private", "Cookie": "private=secret"}
	for _, candidate := range []string{other.URL + "/real.png", s.URL + "/redirect.ico"} {
		body := []byte(`<link rel='icon' href='` + candidate + `'>`)
		if got := GetPageIconHash(context.Background(), c, s.URL+"/app/?token=private", body, network.OptionsRequest{Timeout: time.Second, CustomHeaders: headers}); got != expectedIconHash([]byte("public image")) {
			t.Fatalf("跨源图标抓取失败: %s", got)
		}
	}
}

func FuzzMetadataAttributeParity(f *testing.F) {
	for _, value := range []string{"/favicon.ico", "/i.ico?a=1&notit=2", `a'b"c>&amp;`, "a\x00b\r\nc", "&#x4eac;", "&copya;"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 8192 {
			t.Skip()
		}
		body := `<link data-note="a>b" href="` + html.EscapeString(value) + `" rel='icon'>`
		z := nethtml.NewTokenizer(strings.NewReader(body))
		if z.Next() != nethtml.StartTagToken {
			t.Fatal("规范样例标签无效")
		}
		_, more := z.TagName()
		want := ""
		for more {
			key, val, next := z.TagAttr()
			if string(key) == "href" {
				want = string(val)
			}
			more = next
		}
		for _, got := range []string{metadataAttribute(body[len("<link"):len(body)-1], "href"), metadataAttribute([]byte(body[len("<link"):len(body)-1]), "href")} {
			if got != want {
				t.Fatalf("属性上下文与标准解析不一致: value=%q got=%q want=%q", value, got, want)
			}
		}
	})
}

func FuzzMetadataExtraction(f *testing.F) {
	for _, body := range []string{"", `<link rel='icon' href='/favicon.ico'>`, "<p>京I<span>CP</span>备12345678号-2</p>", `<!--> <link href='/i.ico' rel='icon'>`, `<script><!--<script></script>--></script><p>京ICP备12345678号</p>`, strings.Repeat("x", 1024), "\xff\xfe"} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 256<<10 {
			t.Skip()
		}
		data := []byte(body)
		original := bytes.Clone(data)
		a, b := GetIconURL("https://example.com/app/", body), GetIconURLFromBody("https://example.com/app/", data)
		if a != b || a != GetIconURL("https://example.com/app/", body) {
			t.Fatal("入口或顺序结果不一致")
		}
		if ExtractICPRecord(body) != ExtractICPRecordFromBody(data) {
			t.Fatal("备案号入口不一致")
		}
		if len(ExtractICPRecord(body)) > 96 {
			t.Fatal("备案字段无界")
		}
		if !bytes.Equal(data, original) {
			t.Fatal("修改了借用正文")
		}
		if !strings.HasPrefix(strings.ToLower(a), "data:") {
			u, err := url.Parse(a)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				t.Fatalf("图标地址无效: %q", a)
			}
		}
	})
}

func FuzzDataIconHashParity(f *testing.F) {
	for _, raw := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("x"), 57), []byte{0xff, 0, 0xfe}} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32<<10 {
			t.Skip()
		}
		uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
		got := (&GetIconHash{}).hashDataURL(uri)
		if got != common.Mmh3Hash32(legacyIconBase64(raw)) {
			t.Fatalf("解码哈希不一致: bytes=%d", len(raw))
		}
	})
}

func FuzzICPVisibleRecord(f *testing.F) {
	f.Add(uint64(0), uint8(0))
	f.Add(uint64(63), uint8(1))
	f.Add(uint64(127), uint8(2))
	f.Add(uint64(255), uint8(3))
	f.Fuzz(func(t *testing.T, seed uint64, mode uint8) {
		want := "京iCp备12345678号-2"
		var text strings.Builder
		for i, r := range []rune(want) {
			if (seed>>uint(i%64))&1 != 0 && r >= 0x21 && r <= 0x7e {
				r += 0xfee0
			}
			if mode&1 != 0 {
				fmt.Fprintf(&text, "<span>&#%d;</span>", r)
			} else {
				text.WriteString("<span>")
				text.WriteRune(r)
				text.WriteString("</span>")
			}
			if (seed>>uint((i+17)%64))&1 != 0 {
				text.WriteString(" \n")
			}
		}
		body := `<p><a href="https://beian.miit.gov.cn/">` + text.String() + `</a></p>`
		if mode&2 != 0 {
			var gb strings.Builder
			for _, r := range body {
				switch {
				case r < 128:
					gb.WriteByte(byte(r))
				case r == '京':
					gb.WriteString("\xbe\xa9")
				case r == '备':
					gb.WriteString("\xb1\xb8")
				case r == '号':
					gb.WriteString("\xba\xc5")
				case r >= 0xff01 && r <= 0xff5e:
					gb.WriteByte(0xa3)
					gb.WriteByte(byte(r-0xfee0) + 0x80)
				default:
					t.Fatalf("测试编码不支持 %U", r)
				}
			}
			body = gb.String()
		}
		if got := ExtractICPRecord(body); got != want {
			t.Fatalf("可见备案号漏报: seed=%d mode=%d got=%q", seed, mode, got)
		}
		if got := ExtractICPRecordFromBody([]byte(body)); got != want {
			t.Fatalf("字节备案号漏报: seed=%d mode=%d got=%q", seed, mode, got)
		}
	})
}
