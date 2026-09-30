package sdk_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/cyberspacesec/gxx/utils/common"
)

func TestScanEntryMetadataAfterRedirect(t *testing.T) {
	for _, ct := range []string{"text/html; charset=utf-8", "application/xhtml+xml", ""} {
		t.Run(ct, func(t *testing.T) {
			image := []byte("redirected favicon image")
			hash := strconv.FormatInt(int64(common.Mmh3Hash32(common.Base64Encode(image))), 10)
			var mu sync.Mutex
			calls := map[string]int{}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls[r.URL.RequestURI()]++
				mu.Unlock()
				switch r.URL.Path {
				case "/entry":
					http.Redirect(w, r, "/app/login.html", http.StatusFound)
				case "/assets/real.ico":
					if r.URL.Query().Get("token") != "a+b z" || r.URL.Query().Get("next") != "https://cdn.example.com//x" {
						t.Error("图标签名参数损坏")
					}
					w.Header().Set("Content-Type", "image/png")
					w.Write(image)
				case "/assets/missing.ico":
					http.NotFound(w, r)
				case "/favicon.ico":
					t.Error("有效候选之后仍请求默认图标")
					http.NotFound(w, r)
				default:
					if ct != "" {
						w.Header().Set("Content-Type", ct)
					} else {
						w.Header()["Content-Type"] = nil
					}
					fmt.Fprint(w, `<!DOCTYPE html><html><head><title>入口页面</title><base href='../assets/'><LINK HREF='missing.ico' REL='icon'><link href='real.ico?token=a%2Bb+z&amp;next=https://cdn.example.com//x' rel='icon'></head><body><!-- 京ICP备00000000号 --><a href='https://beian.miit.gov.cn/'>&#20140;ICP<span>备12345678</span>号-2</a></body></html>`)
				}
			}))
			defer s.Close()
			rules := fmt.Sprintf("  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.icon_hash == '%s'\n", hash)
			e := engine(t, rules)
			result, err := e.Scan(context.Background(), s.URL+"/entry")
			if err != nil || result == nil || result.ICP != "京ICP备12345678号-2" || result.Title != "入口页面" || len(result.Matches) != 1 {
				t.Fatalf("入口页元数据或指纹缺失: result=%+v err=%v", result, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if calls["/assets/missing.ico"] != 1 || calls["/assets/real.ico?token=a%2Bb+z&next=https://cdn.example.com//x"] != 1 {
				t.Fatalf("图标候选与规则缓存未共用结果: %v", calls)
			}
		})
	}
}

func TestScanInlineFaviconMatchesHTTPHash(t *testing.T) {
	image := []byte("inline favicon image")
	hash := strconv.FormatInt(int64(common.Mmh3Hash32(common.Base64Encode(image))), 10)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			t.Error("内联图标仍请求默认图标")
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><link href='data:image/png;base64,%s' rel='icon'></head><body>京ICP备12345678号</body></html>`, base64.StdEncoding.EncodeToString(image))
	}))
	defer s.Close()
	rules := fmt.Sprintf("  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.icon_hash == '%s'\n", hash)
	e := engine(t, rules)
	result, err := e.Scan(context.Background(), s.URL)
	if err != nil || len(result.Matches) != 1 || result.ICP != "京ICP备12345678号" {
		t.Fatalf("内联图标没有参与指纹匹配: result=%+v err=%v", result, err)
	}
}
