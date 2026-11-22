package sdk_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cyberspacesec/gxx/sdk"
)

// 图标证据复用计算 icon_hash 的那次请求：图标只请求一次，MMH3 与 response.icon_hash 相同，
// SHA256 与字节数描述完整的图标，原始字节受上限约束；跨源图标标记 CrossOrigin。
func TestIconEvidenceReusesMatchingRequest(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 200)...)
	var iconHits, foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignHits.Add(1)
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	}))
	defer foreign.Close()
	var page atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fav.png" {
			iconHits.Add(1)
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page.Load().(string)))
	}))
	defer server.Close()
	rule := subRuleRule("icon", "/", `response.icon_hash != "0"`, `response.icon_hash`)
	scan := func(t *testing.T, opts ...sdk.Option) *sdk.TargetResult {
		t.Helper()
		e := newRuleEngine(t, map[string]string{"icon": rule}, opts...)
		result, err := e.Scan(context.Background(), server.URL)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Matches) != 1 {
			t.Fatalf("matches=%v", resultIDs(result))
		}
		return result
	}

	page.Store(`<html><head><link rel="icon" href="/fav.png"></head></html>`)
	plain := scan(t)
	if plain.Icon != nil || iconHits.Load() != 1 {
		t.Fatalf("默认不记录证据: icon=%+v hits=%d", plain.Icon, iconHits.Load())
	}
	result := scan(t, sdk.WithIconEvidence(1024))
	icon := result.Icon
	if iconHits.Load() != 2 || icon == nil || icon.URL != server.URL+"/fav.png" || icon.ContentType != "image/png" || icon.Bytes != int64(len(png)) || icon.SHA256 != digest(png) || !bytes.Equal(icon.Data, png) || icon.TooLarge || icon.CrossOrigin {
		t.Fatalf("hits=%d icon=%+v", iconHits.Load(), icon)
	}
	if icon.MMH3 != result.Matches[0].ProductVersion || icon.MMH3 != plain.Matches[0].ProductVersion {
		t.Fatalf("MMH3=%s icon_hash=%s/%s", icon.MMH3, result.Matches[0].ProductVersion, plain.Matches[0].ProductVersion)
	}
	if small := scan(t, sdk.WithIconEvidence(16)).Icon; small == nil || !small.TooLarge || small.Data != nil || small.Bytes != int64(len(png)) || small.SHA256 != digest(png) {
		t.Fatalf("超过上限: %+v", small)
	}

	page.Store(`<html><head><link rel="icon" href="` + foreign.URL + `/logo.png"></head></html>`)
	if cross := scan(t, sdk.WithIconEvidence(1024)).Icon; cross == nil || !cross.CrossOrigin || foreignHits.Load() != 1 || cross.SHA256 != digest(png) {
		t.Fatalf("跨源图标: %+v hits=%d", cross, foreignHits.Load())
	}

	page.Store(`<html><head><link rel="icon" href="data:image/png;base64,` + base64.StdEncoding.EncodeToString(png) + `"></head></html>`)
	if inline := scan(t, sdk.WithIconEvidence(1024)).Icon; inline == nil || inline.URL != "data:image/png;base64," || inline.ContentType != "image/png" || !bytes.Equal(inline.Data, png) || inline.CrossOrigin {
		t.Fatalf("内联图标: %+v", inline)
	}
}
