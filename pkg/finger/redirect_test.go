package finger

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func clientRedirect(t *testing.T, page, body string, header http.Header) (string, string) {
	t.Helper()
	u, err := url.Parse(page)
	if err != nil {
		t.Fatal(err)
	}
	if header == nil {
		header = http.Header{}
	}
	target, kind := ClientRedirect(u, header, []byte(body))
	if target == nil {
		return "", kind
	}
	return target.String(), kind
}

func TestClientRedirectFollowsUnambiguousShells(t *testing.T) {
	const page = "http://a.test/app/"
	cases := []struct {
		name, body, want, kind string
	}{
		{"meta refresh", `<html><head><meta http-equiv="refresh" content="0;url=/login"></head></html>`, "http://a.test/login", RedirectRefresh},
		{"meta 大小写、引号与相对地址", `<META HTTP-EQUIV=Refresh CONTENT="1; URL='index.jsp?a=1&amp;b=2'">`, "http://a.test/app/index.jsp?a=1&b=2", RedirectRefresh},
		{"meta 省略 url=", `<meta http-equiv="refresh" content="3,/next">`, "http://a.test/next", RedirectRefresh},
		{"meta 在真实页面上同样生效", `<html><head><meta http-equiv="refresh" content="5;url=/main"></head><body><form><input name=u></form>` + strings.Repeat("内容", 9000) + `</body></html>`, "http://a.test/main", RedirectRefresh},
		{"base href 参与解析", `<base href="/root/"><meta http-equiv="refresh" content="0;url=x.html">`, "http://a.test/root/x.html", RedirectRefresh},
		{"location.href", `<script>window.location.href="/index.html";</script>`, "http://a.test/index.html", RedirectJavaScript},
		{"location 赋值", `<script type="text/javascript">location='main.do'</script>`, "http://a.test/app/main.do", RedirectJavaScript},
		{"top.location.href", `<script>top.location.href = '/login.jsp';</script>`, "http://a.test/login.jsp", RedirectJavaScript},
		{"document.location", `<script>document.location = "login.php"</script>`, "http://a.test/app/login.php", RedirectJavaScript},
		{"location.replace", `<script>window.location.replace('/web/')</script>`, "http://a.test/web/", RedirectJavaScript},
		{"location.assign", `<script>self.location.assign("/ui")</script>`, "http://a.test/ui", RedirectJavaScript},
		{"旧式 HTML 注释包裹", "<script language=\"javascript\">\n<!--\nwindow.location.href=\"/index.jsp\";\n//-->\n</script>", "http://a.test/index.jsp", RedirectJavaScript},
		{"onload 回调里的跳转", `<script>window.onload=function(){location.href="/main"}</script>`, "http://a.test/main", RedirectJavaScript},
		{"body onload 属性", `<body onload="location.href='/portal'"></body>`, "http://a.test/portal", RedirectJavaScript},
		{"查询串里拼接时间戳（海康）", "<body></body><script>\n\twindow.location.href = \"/doc/page/login.asp?_\" + (new Date()).getTime();\n</script>", "http://a.test/doc/page/login.asp?_", RedirectJavaScript},
		{"meta 与脚本指向同一地址（Jenkins）", `<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/><script>window.location.replace('/login?from=%2F');</script></head><body style='background-color:white; color:white;'>Authentication required</body></html>`, "http://a.test/login?from=%2F", RedirectRefresh},
		{"转义的斜线", `<script>location.href="\/home\/index"</script>`, "http://a.test/home/index", RedirectJavaScript},
		{"查询路由（ThinkPHP）", `<script>window.location="index.php?s=/Home/Index"</script>`, "http://a.test/app/index.php?s=/Home/Index", RedirectJavaScript},
		{"跨资产目标也返回，由调用方决定不跟随", `<script>location.href="https://sso.other.test/login"</script>`, "https://sso.other.test/login", RedirectJavaScript},
		{"少量提示文字", `<p>正在跳转，请稍候...</p><script>location.href="/go"</script><a href="/go">点击这里</a>`, "http://a.test/go", RedirectJavaScript},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := clientRedirect(t, page, tc.body, nil)
			if got != tc.want || kind != tc.kind {
				t.Fatalf("got %q (%s), want %q (%s)", got, kind, tc.want, tc.kind)
			}
		})
	}
}

func TestClientRedirectRejectsAmbiguousOrUnsafe(t *testing.T) {
	const page = "http://a.test/"
	cases := []struct{ name, body string }{
		{"没有跳转", `<html><head><title>x</title></head><body>hello</body></html>`},
		{"定时刷新自身", `<meta http-equiv="refresh" content="30">`},
		{"刷新到自身", `<meta http-equiv="refresh" content="0;url=/">`},
		{"长延迟（会话超时）", `<meta http-equiv="refresh" content="1800;url=/logout">`},
		{"noscript 里的 meta", `<noscript><meta http-equiv="refresh" content="0;url=/nojs"></noscript>`},
		{"javascript: 地址", `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`},
		{"其他 http-equiv", `<meta http-equiv="X-UA-Compatible" content="IE=edge">`},
		{"目标是变量", `<script>location.href = url;</script>`},
		{"路径里拼接变量", `<script>location.href = "/" + lang + "/index.html";</script>`},
		{"路径后拼接", `<script>location.href = "/user/" + id;</script>`},
		{"模板字符串插值", "<script>location.href = `/u/${id}`;</script>"},
		{"按设备分流的两个目标", `<script>if(isMobile){location.href='/m/'}else{location.href='/pc/'}</script>`},
		{"比较而非赋值", `<script>if(location.href == "/login"){run()}</script>`},
		{"严格比较", `<script>if(location.href==="/login"){run()}</script>`},
		{"追加而非赋值", `<script>location.href += "?a=1";</script>`},
		{"只改 hash", `<script>location.hash = "#/login";</script>`},
		{"片段跳转", `<script>location.href = "#/login";</script>`},
		{"其他对象的 location 属性", `<script>data.location = "/beijing"; user.location.href = "/x";</script>`},
		{"声明同名变量", `<script>var location = "/x";</script>`},
		{"字符串里的代码", `<script>document.write('<a onclick="location.href=\'/x\'">go</a>');</script>`},
		{"注释里的代码", "<script>// location.href='/x'\n/* location.href='/y' */</script>"},
		{"字面量上调用方法", `<script>location.href = "/a".concat(x);</script>`},
		{"外链脚本", `<script src="/redirect.js"></script>`},
		{"非脚本类型", `<script type="text/template">location.href="/x"</script>`},
		{"模板元素内", `<template><script>location.href="/x"</script></template>`},
		{"带表单的真实页面", `<form action="/login"><input name="u"></form><script>function out(){location.href="/logout"}</script>`},
		{"带框架的页面", `<iframe src="/main"></iframe><script>location.href="/x"</script>`},
		{"可见文字很多", `<p>` + strings.Repeat("这是一段正文。", 60) + `</p><script>location.href="/x"</script>`},
		{"页面过大", `<script>location.href="/x"</script><!--` + strings.Repeat("x", maxShellBytes) + `-->`},
		{"window.open 不是跳转", `<script>window.open("/x")</script>`},
		{"location.reload", `<script>location.reload()</script>`},
		{"无法解析的地址", `<script>location.href="http://[bad"</script>`},
		{"正则字面量里的引号", `<script>var re = /location.href="\/x"/; go(re);</script>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, kind := clientRedirect(t, page, tc.body, nil); got != "" {
				t.Fatalf("不应识别出跳转: %q (%s)", got, kind)
			}
		})
	}
}

func TestClientRedirectRefreshHeader(t *testing.T) {
	header := http.Header{"Refresh": {"0; url=/console/"}}
	if got, kind := clientRedirect(t, "https://a.test:8443/", "", header); got != "https://a.test:8443/console/" || kind != RedirectRefresh {
		t.Fatalf("got %q (%s)", got, kind)
	}
	if got, _ := clientRedirect(t, "https://a.test/", "", http.Header{"Refresh": {"60"}}); got != "" {
		t.Fatalf("定时刷新不是跳转: %q", got)
	}
}

func FuzzClientRedirect(f *testing.F) {
	f.Add(`<script>location.href="/x"</script>`)
	f.Add(`<meta http-equiv=refresh content="0;url=/y">`)
	f.Add("<script>location.replace(`/a${b}`)//</script>")
	page, _ := url.Parse("http://a.test/")
	f.Fuzz(func(t *testing.T, body string) {
		if target, _ := ClientRedirect(page, http.Header{}, []byte(body)); target != nil && target.Scheme != "http" && target.Scheme != "https" {
			t.Fatalf("非 http/https 目标: %s", target)
		}
	})
}
