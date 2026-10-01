/*
  - Package test
    @Author: zhizhuo
    @IDE：GoLand
    @File: icp_test.go
    @Date: 2025/8/12 下午5:15*
*/
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/v2/pkg/finger"
)

// TestExtractICPFromBaidu 请求百度首页并尝试提取ICP备案信息
func TestExtractICPFromBaidu(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 ICP 测试；设置 GXX_INTEGRATION=1 启用")
	}
	// 设置代理
	//proxyURL, err := url.Parse("http://127.0.0.1:8080")
	//if err != nil {
	//	t.Fatalf("parse proxy URL failed: %v", err)
	//}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{
			//Proxy: http.ProxyURL(proxyURL),
		},
	}

	req, err := http.NewRequest("GET", "https://www.baidu.com/", nil)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}

	// 添加自定义headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("User-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	fmt.Println(string(body))
	icp := finger.ExtractICPRecord(string(body))
	if icp == "" {
		t.Logf("No ICP record found on baidu homepage")
	} else {
		t.Logf("Extracted ICP: %s", icp)
	}
}
