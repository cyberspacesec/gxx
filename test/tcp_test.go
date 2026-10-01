package main

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/network"
)

func TestTcp(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 TCP/SOCKS5 测试；设置 GXX_INTEGRATION=1 启用")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := network.DialContext(ctx, "tcp", "www.baidu.com:80", "socks5://127.0.0.1:10808", 5*time.Second, false, "", false)
	if err != nil {
		t.Fatalf("SOCKS5 连接失败：%v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://www.baidu.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("发送请求失败：%v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("读取响应失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		t.Fatalf("HTTP 状态异常：%d", resp.StatusCode)
	}
}
