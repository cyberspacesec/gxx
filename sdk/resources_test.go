package sdk_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cyberspacesec/gxx/sdk"
)

// 附属资源：只请求最终页面所在资产，正文保留不超过上限，摘要覆盖实际读取的正文；
// 只跟随同站跳转；默认不请求。
func TestResourcesFromFinalAsset(t *testing.T) {
	robots := []byte("User-agent: *\nDisallow: /admin\n")
	sitemap := bytes.Repeat([]byte("<url><loc>/a</loc></url>"), 4000)
	var foreignHits, entryResourceHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignHits.Add(1)
		_, _ = w.Write([]byte("foreign"))
	}))
	defer foreign.Close()
	foreignURL := strings.Replace(foreign.URL, "127.0.0.1", "localhost", 1)
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			http.Redirect(w, r, "/real-robots.txt", http.StatusMovedPermanently)
		case "/real-robots.txt":
			_, _ = w.Write(robots)
		case "/sitemap.xml":
			_, _ = w.Write(sitemap)
		default:
			_, _ = w.Write([]byte("<html>final</html>"))
		}
	}))
	defer final.Close()
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			entryResourceHits.Add(1)
		}
		http.Redirect(w, r, final.URL+"/home", http.StatusFound)
	}))
	defer entry.Close()
	rules := map[string]string{"page": exprRule("page", `response.status == 200`)}

	plain := newRuleEngine(t, rules)
	if result, err := plain.Scan(context.Background(), entry.URL); err != nil || result.Resources != nil {
		t.Fatalf("默认不读取附属资源: %+v %v", result.Resources, err)
	}
	e := newRuleEngine(t, rules, sdk.WithResources(sdk.ResourceOptions{Robots: true, Sitemap: true, MaxBytes: 64}))
	var kinds []sdk.RequestKind
	result, err := e.ScanWith(context.Background(), entry.URL, sdk.ScanObserver(func(ex sdk.Exchange) {
		if ex.Kind == sdk.RequestResource {
			kinds = append(kinds, ex.Kind)
		}
	}, sdk.ExchangeLimits{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resources) != 2 || entryResourceHits.Load() != 0 || len(kinds) != 3 {
		t.Fatalf("resources=%+v entryHits=%d resourceExchanges=%d", result.Resources, entryResourceHits.Load(), len(kinds))
	}
	got := result.Resources[0]
	if got.Kind != "robots" || got.URL != final.URL+"/real-robots.txt" || got.StatusCode != 200 || !bytes.Equal(got.Body, robots) || got.BodyBytes != int64(len(robots)) || got.SHA256 != digest(robots) || got.Truncated {
		t.Fatalf("robots=%+v", got)
	}
	got = result.Resources[1]
	if got.Kind != "sitemap" || !bytes.Equal(got.Body, sitemap[:64]) || got.BodyBytes != int64(len(sitemap)) || got.SHA256 != digest(sitemap) || !got.Truncated {
		t.Fatalf("sitemap: kind=%s body=%d bytes=%d truncated=%v", got.Kind, len(got.Body), got.BodyBytes, got.Truncated)
	}

	// 指向其他站点的跳转不跟随：返回 30x 本身，对方收不到请求。
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.Redirect(w, r, foreignURL+"/robots.txt", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("<html>cross</html>"))
	}))
	defer cross.Close()
	only := newRuleEngine(t, rules, sdk.WithResources(sdk.ResourceOptions{Robots: true}))
	result, err = only.Scan(context.Background(), cross.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resources) != 1 || result.Resources[0].StatusCode != http.StatusFound || foreignHits.Load() != 0 {
		t.Fatalf("resources=%+v foreignHits=%d", result.Resources, foreignHits.Load())
	}
}
