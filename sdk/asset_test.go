package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// ruleLibrary 把 id → 规则片段写成规则目录并创建引擎。
func ruleLibrary(t *testing.T, rules map[string]string) *sdk.Engine {
	t.Helper()
	dir := t.TempDir()
	for id, body := range rules {
		data := "id: " + id + "\ninfo:\n  name: " + id + "\nrules:\n" + body
		if !strings.Contains(body, "\nexpression:") {
			data += "expression: r0()\n"
		}
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithTimeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func rootRule(expression string) string {
	return "  r0:\n    request:\n      method: GET\n      path: /\n    expression: '" + expression + "'\n"
}

func matchedIDs(result *sdk.TargetResult) []string {
	ids := make([]string, 0, len(result.Matches))
	for _, match := range result.Matches {
		ids = append(ids, match.Info.ID)
	}
	slices.Sort(ids)
	return ids
}

// requestLog 记录服务端收到的请求。
type requestLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *requestLog) add(r *http.Request) {
	l.mu.Lock()
	l.seen = append(l.seen, r.Method+" "+r.URL.RequestURI())
	l.mu.Unlock()
}

func (l *requestLog) count(entry string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, item := range l.seen {
		if item == entry {
			n++
		}
	}
	return n
}

func (l *requestLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.seen)
}

// 资产 = 协议 + 主机 + 端口。30x 指向其他资产时停在 30x：不请求对方，
// 结果描述的是 30x 响应本身，对方页面的标题、Server 与指纹不会记到本资产名下。
func TestScanStopsAtCrossAssetRedirect(t *testing.T) {
	var foreignLog requestLog
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignLog.add(r)
		w.Header().Set("Server", "asset-B")
		fmt.Fprint(w, "<html><head><title>B 的登录页</title></head><body>marker-b</body></html>")
	}))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "asset-A")
		http.Redirect(w, r, foreign.URL+"/portal", http.StatusFound)
	}))
	defer origin.Close()

	e := ruleLibrary(t, map[string]string{
		"foreign-body": rootRule(`response.body.bcontains(b"marker-b")`),
		"redirector":   rootRule(`response.status == 302 && response.raw_header.ibcontains(b"Location: ` + foreign.URL + `/portal")`),
	})
	result, err := e.Scan(context.Background(), origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := foreignLog.all(); len(got) != 0 {
		t.Fatalf("向其他资产发出了请求: %v", got)
	}
	if result.StatusCode != http.StatusFound || strings.Contains(result.Title, "B") || result.Server.OriginalServer != "asset-A" {
		t.Fatalf("结果混入了其他资产: status=%d title=%q server=%+v", result.StatusCode, result.Title, result.Server)
	}
	if result.RedirectTo != foreign.URL+"/portal" || result.FinalURL != origin.URL {
		t.Fatalf("redirect_to=%q final_url=%q", result.RedirectTo, result.FinalURL)
	}
	want := []sdk.Redirect{{Type: "http", Status: 302, From: origin.URL, To: foreign.URL + "/portal", Followed: false}}
	if !slices.Equal(result.Redirects, want) {
		t.Fatalf("redirects=%+v", result.Redirects)
	}
	if got := matchedIDs(result); !slices.Equal(got, []string{"redirector"}) {
		t.Fatalf("matches=%v", got)
	}
	info, err := e.GetBaseInfo(context.Background(), origin.URL)
	if err != nil || info.RedirectTo != foreign.URL+"/portal" || info.StatusCode != http.StatusFound {
		t.Fatalf("GetBaseInfo: %+v err=%v", info, err)
	}
}

// 资产内的 30x 会跟随，链上每一页都参与根路径规则：30x 响应本身和最终页面都能命中。
// 不跟随重定向的根路径规则只看第一页，并复用入口响应，不再另发请求。
func TestScanMatchesEveryPageInAssetChain(t *testing.T) {
	var log requestLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Set-Cookie", "SKYLAR=1; Path=/")
			http.Redirect(w, r, "/login?refer=%2F", http.StatusFound)
		case "/login":
			fmt.Fprint(w, "<html><head><title>登录</title></head><body>login-form-marker</body></html>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := ruleLibrary(t, map[string]string{
		"entry-302":  rootRule(`response.status == 302 && response.raw_header.ibcontains(b"Location: /login?refer=%2F") && response.raw_header.ibcontains(b"Set-Cookie: SKYLAR")`),
		"final-page": rootRule(`response.status == 200 && response.body.bcontains(b"login-form-marker")`),
		"no-follow":  "  r0:\n    request:\n      method: GET\n      path: /\n      follow_redirects: false\n    expression: response.status == 302\n",
		"both":       rootRule(`response.status == 302`) + strings.Replace(rootRule(`response.body.bcontains(b"login-form-marker")`), "r0:", "r1:", 1) + "expression: r0() && r1()\n",
		"absent":     rootRule(`response.body.bcontains(b"not-there")`),
	})
	result, err := e.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// both 的两条规则分别落在不同页面上，单独任何一页都不满足，不应命中。
	if got := matchedIDs(result); !slices.Equal(got, []string{"entry-302", "final-page", "no-follow"}) {
		t.Fatalf("matches=%v", got)
	}
	if result.StatusCode != http.StatusOK || result.Title != "登录" || result.FinalURL != srv.URL+"/login?refer=%2F" || result.RedirectTo != "" {
		t.Fatalf("status=%d title=%q final=%q redirect_to=%q", result.StatusCode, result.Title, result.FinalURL, result.RedirectTo)
	}
	if len(result.Redirects) != 1 || !result.Redirects[0].Followed || result.Redirects[0].Status != 302 {
		t.Fatalf("redirects=%+v", result.Redirects)
	}
	if n := log.count("GET /"); n != 1 {
		t.Fatalf("入口被请求了 %d 次，规则应复用入口响应: %v", n, log.all())
	}
	if n := log.count("GET /login?refer=%2F"); n != 1 {
		t.Fatalf("最终页被请求了 %d 次: %v", n, log.all())
	}
}

// 客户端跳转（meta refresh、跳转壳里的脚本）只在资产内跟随，壳和落地页都参与匹配；
// 指向其他资产的目标不访问，记入 RedirectTo。
func TestScanFollowsClientRedirectWithinAsset(t *testing.T) {
	var foreignLog requestLog
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignLog.add(r) }))
	defer foreign.Close()
	var log requestLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><script>window.location.href = "/doc/page/login.asp?_" + (new Date()).getTime();</script></head><body></body></html>`)
		case "/doc/page/login.asp":
			fmt.Fprint(w, `<html><head><title>设备登录</title><meta http-equiv="refresh" content="0;url=/final"></head><body>step-two</body></html>`)
		case "/final":
			fmt.Fprint(w, `<html><head><title>控制台</title></head><body>console-marker</body></html>`)
		case "/outbound":
			fmt.Fprint(w, `<html><head><script>location.replace("`+foreign.URL+`/sso");</script></head></html>`)
		case "/loop":
			fmt.Fprint(w, `<meta http-equiv="refresh" content="0;url=/loop2">`)
		case "/loop2":
			fmt.Fprint(w, `<meta http-equiv="refresh" content="0;url=/loop">`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := ruleLibrary(t, map[string]string{
		"shell":   rootRule(`response.body.bcontains(b"/doc/page/login.asp")`),
		"middle":  rootRule(`response.body.bcontains(b"step-two")`),
		"landing": rootRule(`response.body.bcontains(b"console-marker")`),
	})
	result, err := e.Scan(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := matchedIDs(result); !slices.Equal(got, []string{"landing", "middle", "shell"}) {
		t.Fatalf("matches=%v", got)
	}
	if result.Title != "控制台" || result.FinalURL != srv.URL+"/final" {
		t.Fatalf("title=%q final=%q", result.Title, result.FinalURL)
	}
	types := make([]string, 0, len(result.Redirects))
	for _, hop := range result.Redirects {
		types = append(types, hop.Type)
	}
	if !slices.Equal(types, []string{"javascript", "refresh"}) {
		t.Fatalf("redirects=%+v", result.Redirects)
	}
	if got := log.all(); !slices.Equal(got[:3], []string{"GET /", "GET /doc/page/login.asp?_", "GET /final"}) {
		t.Fatalf("请求顺序: %v", got)
	}

	result, err = e.Scan(context.Background(), srv.URL+"/outbound")
	if err != nil {
		t.Fatal(err)
	}
	if result.RedirectTo != foreign.URL+"/sso" || len(foreignLog.all()) != 0 || result.FinalURL != srv.URL+"/outbound" {
		t.Fatalf("redirect_to=%q final=%q foreign=%v", result.RedirectTo, result.FinalURL, foreignLog.all())
	}
	if hop := result.Redirects[0]; hop.Type != "javascript" || hop.Followed {
		t.Fatalf("redirects=%+v", result.Redirects)
	}

	// 回环：/loop → /loop2 → /loop 在回到已访问页面时停下。
	if result, err = e.Scan(context.Background(), srv.URL+"/loop"); err != nil || result.FinalURL != srv.URL+"/loop2" || len(result.Redirects) != 1 {
		t.Fatalf("loop: %+v err=%v", result, err)
	}
}

// 目标的路径是规则路径的前缀；查询串只属于目标页面本身，片段不发往服务端。
func TestRulePathsRelativeToTarget(t *testing.T) {
	var log requestLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	e := ruleLibrary(t, map[string]string{
		"paths": rootRule(`response.status == 200`) + "  r1:\n    request:\n      method: GET\n      path: /admin\n    expression: response.status == 200\nexpression: r0() && r1()\n",
	})
	cases := []struct {
		target string
		want   []string
	}{
		{srv.URL, []string{"GET /", "GET /admin"}},
		{srv.URL + "/app/", []string{"GET /app/", "GET /app/admin"}},
		{srv.URL + "/?x=1", []string{"GET /?x=1", "GET /admin"}},
		{srv.URL + "/app/index.php?id=1#frag", []string{"GET /app/index.php?id=1", "GET /app/index.php/admin"}},
		{strings.TrimPrefix(srv.URL, "http://"), []string{"GET /", "GET /admin"}},
	}
	for _, c := range cases {
		log.mu.Lock()
		log.seen = nil
		log.mu.Unlock()
		result, err := e.Scan(context.Background(), c.target)
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		got := slices.DeleteFunc(log.all(), func(entry string) bool { return strings.Contains(entry, "favicon") })
		if !slices.Equal(got, c.want) || len(result.Matches) != 1 {
			t.Errorf("%s: requests=%v matches=%d, want %v", c.target, got, len(result.Matches), c.want)
		}
	}
}
