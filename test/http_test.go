/*
  - Package request
    @Author: zhizhuo
    @IDE：GoLand
    @File: http_test.go
    @Date: 2025/2/25 下午3:16*
*/
package main

import (
	"crypto/tls"
	"fmt"
	"github.com/cyberspacesec/gxx/pkg/network"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestTCPClient(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 TCP 测试；设置 GXX_INTEGRATION=1 启用")
	}

	address := "www.baidu.com"

	conf := network.TcpOrUdpConfig{
		Network:      "tcp",
		MaxRetries:   3,
		ReadSize:     2048,
		DialTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
	}

	client, err := network.NewClientContext(context.Background(), address, conf)
	if err != nil {
		t.Fatalf("创建 TCP 客户端失败：%v", err)
	}
	defer client.Close()

	message := []byte("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n")
	err = client.Send(message)
	if err != nil {
		t.Fatalf("发送 TCP 请求失败：%v", err)
	}
	fmt.Println("Data sent successfully")

	response, err := client.Receive()
	if err != nil {
		t.Fatalf("读取 TCP 响应失败：%v", err)
	}
	fmt.Printf("Received response: %s\n", string(response))
}
func TestUDPClient(t *testing.T) {
	address := startUDPEcho(t)
	conf := network.TcpOrUdpConfig{
		Network:      "udp",
		MaxRetries:   1,
		ReadSize:     2048,
		DialTimeout:  time.Second,
		WriteTimeout: time.Second,
		ReadTimeout:  time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := network.NewClientContext(ctx, address, conf)
	if err != nil {
		t.Fatalf("创建 UDP 客户端失败：%v", err)
	}
	defer client.Close()

	message := []byte("Hello, UDP server!")
	err = client.Send(message)
	if err != nil {
		t.Fatalf("发送 UDP 数据失败：%v", err)
	}

	response, err := client.Receive()
	if err != nil || string(response) != string(message) {
		t.Fatalf("UDP 应答不一致：response=%q err=%v", response, err)
	}
}

func TestHttpCtxClient(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 HTTP 测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	options := network.OptionsRequest{
		Timeout:            10 * time.Second, // 使用与context相同的超时时间
		FollowRedirects:    true,
		InsecureSkipVerify: true,
		CustomHeaders: map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		},
	}
	defer cancel()

	fmt.Println("开始发送请求...")
	fmt.Printf("请求URL: %s\n", url)
	fmt.Printf("使用代理: %s\n", options.Proxy)
	fmt.Printf("超时设置: %v\n", options.Timeout)

	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()
	resp, err := client.SendRequestHttp(ctx, "GET", url, "", options)
	if err != nil {
		fmt.Printf("发送请求出错，错误信息：%v\n", err)
		return
	}
	if resp == nil {
		fmt.Println("响应为空")
		return
	}
	defer func(Body io.ReadCloser) {
		if Body != nil {
			_ = Body.Close()
		}
	}(resp.Body)

	fmt.Printf("响应状态码: %d\n", resp.StatusCode)

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应体出错: %v\n", err)
		return
	}
	fmt.Printf("响应内容长度: %d bytes\n", len(body))
	fmt.Printf("响应内容: %s\n", string(body))
}

func TestHTTPRequest(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 HTTPS 测试；设置 GXX_INTEGRATION=1 启用")
	}
	// 创建自定义的 Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 注意：仅用于测试目的，不推荐用于生产环境
			MinVersion:         tls.VersionTLS10,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			},
		},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间
	}

	resp, err := client.Get("https://www.baidu.com/")
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("响应状态码: %d\n", resp.StatusCode)
}
