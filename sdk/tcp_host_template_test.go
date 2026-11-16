package sdk_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// bannerServer 在 network/address 上监听，收到任意数据后回写 SSH 横幅。
func bannerServer(t *testing.T, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Skipf("无法监听 %s: %v", address, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buffer := make([]byte, 64)
				if _, err := conn.Read(buffer); err == nil {
					_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6"))
				}
			}()
		}
	}()
	return listener
}

// TestTCPRuleBracketHostTemplate 锁定文档推荐的 TCP/UDP 地址写法：
// `set: domain: request.url.domain` 加 `host: "[{{domain}}]:端口"`。
//
// request.url.host 带着目标自身的端口，拼上规则端口会得到 "1.2.3.4:8080:22"；
// request.url.domain 去掉了端口，但 IPv6 也没有方括号。方括号写法对域名、IPv4
// 与 IPv6 目标都能得到唯一的拨号地址，无论目标是否自带端口。
func TestTCPRuleBracketHostTemplate(t *testing.T) {
	cases := []struct {
		name, listen, target string
	}{
		{"ipv4 目标自带其他端口", "127.0.0.1:0", "127.0.0.1:1"},
		{"ipv4 URL 目标", "127.0.0.1:0", "http://127.0.0.1:1/path"},
		{"域名目标", "127.0.0.1:0", "localhost:1"},
		{"ipv6 目标", "[::1]:0", "[::1]:1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			listener := bannerServer(t, c.listen)
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			rule := fmt.Sprintf("id: bracket\ninfo:\n  name: bracket\nset:\n  domain: request.url.domain\nrules:\n"+
				"  r0:\n    request:\n      type: tcp\n      host: \"[{{domain}}]:%s\"\n      data: \"\\n\"\n"+
				"    expression: response.raw.bcontains(b\"SSH-\")\nexpression: r0()\n", port)
			path := filepath.Join(t.TempDir(), "bracket.yaml")
			if err := os.WriteFile(path, []byte(rule), 0o600); err != nil {
				t.Fatal(err)
			}
			e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocYaml: path}), sdk.WithTimeout(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			result, err := e.Scan(context.Background(), c.target)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Matches) != 1 || result.Matches[0].Info.ID != "bracket" {
				t.Fatalf("目标 %s 未通过方括号模板命中: %+v", c.target, result.Matches)
			}
		})
	}
}
