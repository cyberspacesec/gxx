package sdk_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// memRules 把规则内容放进内存文件系统，文件名即规则标识。
func memRules(rules map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for id, body := range rules {
		fsys[id+".yaml"] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

// exprRule 生成一条请求根路径、按 expression 判断的规则。
func exprRule(id, expression string) string {
	return "id: " + id + "\ninfo:\n  name: " + id + "\n  author: test\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: " + expression + "\nexpression: r0()\n"
}

func newRuleEngine(t *testing.T, rules map[string]string, opts ...sdk.Option) *sdk.Engine {
	t.Helper()
	e, err := sdk.NewEngine(context.Background(), append([]sdk.Option{sdk.WithRuleFS(memRules(rules), "."), sdk.WithTimeout(3 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func resultIDs(result *sdk.TargetResult) []string {
	var ids []string
	for _, match := range result.Matches {
		ids = append(ids, match.Info.ID)
	}
	return ids
}

// rawTLSServer 在 TLS 上返回手写的响应，用于控制响应头的顺序与大小写。
func rawTLSServer(t *testing.T, response string) string {
	t.Helper()
	certServer := httptest.NewUnstartedServer(http.NotFoundHandler())
	certServer.StartTLS()
	config := certServer.TLS.Clone()
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					if _, err := http.ReadRequest(reader); err != nil {
						return
					}
					if _, err := io.WriteString(conn, response); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return "https://" + ln.Addr().String()
}

// 扫描结果携带最终页面的 TLS 摘要与响应头顺序；表达式可以使用 response.tls_version、
// response.cipher_suite、response.ja3s 与 response.jarm（未启用 JARM 时为空串）。
func TestScanReportsTLSInfoAndHeaderOrder(t *testing.T) {
	body := "<html><title>tls</title></html>"
	target := rawTLSServer(t, "HTTP/1.1 200 OK\r\nX-Zeta: 1\r\nContent-Type: text/html\r\nx-alpha: 2\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	e := newRuleEngine(t, map[string]string{
		"tls-vars":  exprRule("tls-vars", `response.tls_version.startsWith("TLS 1.") && response.cipher_suite.startsWith("TLS_") && size(response.ja3s) == 32 && response.jarm == ""`),
		"plain-tls": exprRule("plain-tls", `response.tls_version == ""`),
	})
	result, err := e.Scan(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if got := resultIDs(result); !reflect.DeepEqual(got, []string{"tls-vars"}) {
		t.Fatalf("matches=%v", got)
	}
	if result.TLS == nil || !strings.HasPrefix(result.TLS.Version, "TLS 1.") || len(result.TLS.JA3S) != 32 || result.TLS.JARM != "" {
		t.Fatalf("TLS=%+v", result.TLS)
	}
	want := []string{"X-Zeta", "Content-Type", "x-alpha", "Set-Cookie", "Set-Cookie", "Content-Length"}
	if !reflect.DeepEqual(result.HeaderOrder, want) {
		t.Fatalf("HeaderOrder=%q", result.HeaderOrder)
	}
	// 原始响应头按同一顺序写出，名称为规范形式。
	if !strings.HasPrefix(result.Headers, "HTTP/1.1 200 OK\nX-Zeta: 1\nContent-Type: text/html\nX-Alpha: 2\nSet-Cookie: a=1\nSet-Cookie: b=2\nContent-Length: ") {
		t.Fatalf("Headers=%q", result.Headers)
	}
}

// 明文目标没有 TLS 摘要，TLS 变量为空串。
func TestPlainTargetHasNoTLSInfo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	e := newRuleEngine(t, map[string]string{"plain": exprRule("plain", `response.tls_version == "" && response.ja3s == "" && response.cipher_suite == ""`)})
	result, err := e.Scan(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if result.TLS != nil || len(result.Matches) != 1 || len(result.HeaderOrder) == 0 {
		t.Fatalf("TLS=%+v matches=%v order=%v", result.TLS, resultIDs(result), result.HeaderOrder)
	}
}
