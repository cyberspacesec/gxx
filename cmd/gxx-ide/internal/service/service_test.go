package service

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLibraryRestrictsPathsAndPreservesFailedSaves(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	s := NewLibraryService()
	if _, e := s.List(dir, false); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "a.yaml")
	if e := s.Save(&model.SaveYAMLInput{Path: path, Content: "id: a"}); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(&model.SaveYAMLInput{Path: path, Content: "rules: ["}); e == nil {
		t.Fatal("invalid YAML saved")
	}
	r, e := s.Load(path)
	if e != nil || r.Content != "id: a" {
		t.Fatalf("%+v %v", r, e)
	}
	external := filepath.Join(outside, "b.yaml")
	os.WriteFile(external, []byte("id: b"), 0600)
	if _, e := s.Load(external); e == nil {
		t.Fatal("external path allowed")
	}
	link := filepath.Join(dir, "escape")
	if e := os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	escaped := filepath.Join(link, "b.yaml")
	if _, e := s.Load(escaped); e == nil {
		t.Fatal("symlink escaped root")
	}
	if e := s.Save(&model.SaveYAMLInput{Path: escaped, Content: "id: replaced"}); e == nil {
		t.Fatal("symlink save escaped root")
	}
	data, _ := os.ReadFile(external)
	if string(data) != "id: b" {
		t.Fatal("external content changed")
	}
	if e := s.Save(&model.SaveYAMLInput{Path: filepath.Join(dir, "plain.conf"), Content: "id: a"}); e == nil {
		t.Fatal("non YAML allowed")
	}
}
func TestRawRespectsCancellationAndProxy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	in := &model.SendRequestInput{Mode: model.RequestModeRaw, Raw: "GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n\r\n", Proxy: "http://127.0.0.1:1", TimeoutSeconds: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := NewRequestService().Send(ctx, in); e == nil {
		t.Fatal("cancellation ignored")
	}
	if _, e := NewRequestService().Send(context.Background(), in); e == nil {
		t.Fatal("proxy ignored")
	}
	if hits.Load() != 0 {
		t.Fatal("sent direct request")
	}
}
func TestCELDebugCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewFingerService().EvaluateCELContext(ctx, &model.EvaluateCELInput{Expression: "sleep(1000)"})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("%v %v", time.Since(start), err)
	}
}

func TestFingerprintOutputsRequireSuccessfulRuleAndExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "version/1.2.3")
	}))
	defer server.Close()
	for _, extract := range []string{`"version/(?<version>[0-9.]+)".bsubmatch(response.body)["version"]`, `"[".bsubmatch(response.body)["version"]`} {
		yaml := "id: output\ninfo:\n  name: 输出测试\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: false\n    output:\n      unmatch_output: '\"incorrect\"'\n  r1:\n    request:\n      method: GET\n      path: /\n    expression: true\n    output:\n      product_version: '" + extract + "'\nexpression: r1()\n"
		result, err := NewFingerService().Run(context.Background(), &model.RunFingerprintInput{YAML: yaml, Target: server.URL, TimeoutSeconds: 2})
		if err != nil || !result.FinalResult {
			t.Fatalf("%+v %v", result, err)
		}
		found := false
		for _, variable := range result.Variables {
			if variable.Key == "unmatch_output" {
				t.Fatal("未命中子规则输出出现在调试变量中")
			}
			if variable.Key == "product_version" {
				found = true
				if !strings.Contains(variable.Value, "1.2.3") {
					t.Fatalf("提取表达式原文成为版本: %+v", variable)
				}
			}
		}
		if found == strings.Contains(extract, `"["`) {
			t.Fatalf("提取失败仍返回版本或成功版本缺失: %+v", result.Variables)
		}
	}
}

// TestEnsurePortAndHostOnlyHandleIPv6 锁定 raw 请求的地址拆分对 IPv6 正确。
// 回归点：ensurePort 用 strings.Contains(":") 判断端口，裸 IPv6（含括号）
// 必然含冒号，导致不补端口直接拨号；hostOnly 用 LastIndex(":") 切分，
// 把 "[::1]" 截成 "[:" 当作 TLS ServerName。
func TestEnsurePortAndHostOnlyHandleIPv6(t *testing.T) {
	for _, tc := range []struct {
		name     string
		host     string
		tls      bool
		wantAddr string
		wantSNI  string
	}{
		{name: "裸IPv6带括号补80", host: "[::1]", wantAddr: "[::1]:80", wantSNI: "::1"},
		{name: "裸IPv6带括号补443", host: "[::1]", tls: true, wantAddr: "[::1]:443", wantSNI: "::1"},
		{name: "裸IPv6无括号补齐", host: "::1", wantAddr: "[::1]:80", wantSNI: "::1"},
		{name: "IPv6显式端口保留", host: "[::1]:8080", wantAddr: "[::1]:8080", wantSNI: "::1"},
		{name: "IPv6带zone", host: "[fe80::1%25eth0]", wantAddr: "[fe80::1%25eth0]:80", wantSNI: "fe80::1%25eth0"},
		{name: "域名补80", host: "example.com", wantAddr: "example.com:80", wantSNI: "example.com"},
		{name: "域名补443", host: "example.com", tls: true, wantAddr: "example.com:443", wantSNI: "example.com"},
		{name: "域名显式端口保留", host: "example.com:8443", wantAddr: "example.com:8443", wantSNI: "example.com"},
		{name: "IPv4补80", host: "127.0.0.1", wantAddr: "127.0.0.1:80", wantSNI: "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if addr := ensurePort(tc.host, tc.tls); addr != tc.wantAddr {
				t.Errorf("ensurePort(%q, %v) = %q，期望 %q", tc.host, tc.tls, addr, tc.wantAddr)
			}
			if sni := hostOnly(tc.host); sni != tc.wantSNI {
				t.Errorf("hostOnly(%q) = %q，期望 %q", tc.host, sni, tc.wantSNI)
			}
		})
	}
}

// set 块在请求发出前求值：文档推荐的 TCP 写法依赖 request.url.domain，调试时必须可用。
func TestRunResolvesTargetVariablesInSet(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 16)
				if _, err := conn.Read(buffer); err == nil {
					_, _ = conn.Write([]byte("SSH-2.0-test"))
				}
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	yaml := "id: tcp\ninfo:\n  name: tcp\nset:\n  domain: request.url.domain\nrules:\n  r0:\n    request:\n      type: tcp\n      host: \"[{{domain}}]:" + port + "\"\n      data: \"\\n\"\n    expression: response.raw.bcontains(b\"SSH-\")\nexpression: r0()\n"
	out, err := NewFingerService().Run(context.Background(), &model.RunFingerprintInput{YAML: yaml, Target: "http://127.0.0.1:1/x", TimeoutSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !out.FinalResult {
		t.Fatalf("TCP 规则未命中: %+v", out.Rules)
	}
}

// 调试结果与扫描一致：匹配入口页的规则依次在入口跳转链的每一页上评估。
func TestRunEvaluatesEveryEntryPage(t *testing.T) {
	var rootHits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			rootHits.Add(1)
			w.Header().Set("Server", "Microsoft-IIS/10.0")
			http.Redirect(w, r, "/owa/", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><head><title>Outlook</title></head></html>")
	}))
	defer server.Close()
	rule := func(expression string) string {
		return "id: demo\ninfo:\n  name: demo\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: '" + expression + "'\nexpression: r0()\n"
	}
	run := func(yaml string) *model.RunFingerprintOutput {
		t.Helper()
		out, err := NewFingerService().Run(context.Background(), &model.RunFingerprintInput{YAML: yaml, Target: server.URL, TimeoutSeconds: 3})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 入口的 302 响应本身命中，状态码与地址指向 302 那一页。
	out := run(rule(`response.status == 302 && response.raw_header.ibcontains(b"Location: /owa/")`))
	if !out.FinalResult || out.Rules[0].StatusCode != 302 || out.Rules[0].URLEvaluated != server.URL {
		t.Fatalf("入口 302 未参与匹配: %+v", out.Rules[0])
	}
	// 最后一页同样可以命中，且优先于更早的页面。
	out = run(rule(`response.body.bcontains(b"Outlook")`))
	if !out.FinalResult || out.Rules[0].StatusCode != 200 || !strings.HasSuffix(out.Rules[0].URLEvaluated, "/owa/") {
		t.Fatalf("最后一页未命中: %+v", out.Rules[0])
	}
	// 都不满足时展示最后一页的结果。
	out = run(rule(`response.status == 500`))
	if out.FinalResult || out.Rules[0].StatusCode != 200 {
		t.Fatalf("未命中时应展示最后一页: %+v", out.Rules[0])
	}
	// 入口页规则复用跳转链上的响应，不再另发请求。
	rootHits.Store(0)
	run(rule(`response.status == 302`))
	if n := rootHits.Load(); n != 1 {
		t.Fatalf("入口被请求了 %d 次", n)
	}
	// 规则声明不跟随时只看第一个响应。
	out = run(strings.Replace(rule(`response.status == 302`), "      path: /\n", "      path: /\n      follow_redirects: false\n", 1))
	if !out.FinalResult || out.Rules[0].StatusCode != 302 {
		t.Fatalf("关闭跟随后应匹配 302: %+v", out.Rules[0])
	}
}
