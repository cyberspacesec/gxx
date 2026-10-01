/*
  - Package main
    @Author: zhizhuo
    @IDE：GoLand
    @File: request_test.go
    @Date: 2025/4/21 上午9:42*
*/
package main

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"os"
	"testing"
	"time"
)

func TestProtocol(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网协议探测测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	proxy := "http://127.0.0.1:8080"
	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()
	fmt.Println(fmt.Sprintf("原始url: %s", url))
	if checkedURL, err := client.CheckProtocol(context.Background(), url, proxy, 10*time.Second); err == nil && checkedURL != "" {
		url = checkedURL
	}
	fmt.Println(fmt.Sprintf("请求协议修正后url: %s", url))
}
