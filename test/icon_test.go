/*
  - Package main
    @Author: zhizhuo
    @IDE：GoLand
    @File: icon_test.go
    @Date: 2025/4/17 上午9:11*
*/
package main

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestGetIconHash(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 icon hash 测试；设置 GXX_INTEGRATION=1 启用")
	}
	iconUrl := "https://www.baidu.com/favicon.ico"
	proxy := "http://127.0.0.1:8080"
	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()
	iconHash := finger.NewGetIconHash(iconUrl, proxy).WithHTTPClient(client).Run(context.Background())
	fmt.Println(fmt.Sprintf("iconHash: %s", iconHash))
}

func TestGetIconUrl(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 icon 测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	proxy := "http://127.0.0.1:8080"
	option := network.OptionsRequest{
		Timeout:            10 * time.Second, // 设置更合理的超时时间
		FollowRedirects:    true,             // 允许重定向
		InsecureSkipVerify: true,             // 忽略SSL证书验证
		Proxy:              proxy,
	}

	// 创建带超时的上下文
	//ctx, cancel := context.WithTimeout(context.Background(), option.Timeout)
	//defer cancel()

	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()
	resp, err := client.SendRequestHttp(context.Background(), http.MethodGet, url, "", option)
	if err != nil {
		t.Logf("请求失败: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Logf("读取响应体失败: %v", err)
		return
	}

	t.Logf("状态码: %d", resp.StatusCode)
	t.Logf("响应体长度: %d bytes", len(body))
	// 获取请求之后的url地址
	lastUrl := resp.Request.URL.String()
	iconUrl := finger.GetIconURL(lastUrl, string(body))
	t.Logf("提取到iconUrl: %s", iconUrl)

	if iconUrl != "" {
		iconHash := finger.NewGetIconHash(iconUrl, "").WithHTTPClient(client).Run(context.Background())
		t.Logf("iconHash: %s", iconHash)
	}
}
