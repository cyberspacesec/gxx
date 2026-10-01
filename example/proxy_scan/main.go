/*
proxy_scan 演示通过 HTTP / SOCKS5 代理扫描，并启用 per-host 限流。

  - WithProxy 设置代理地址
  - WithRateLimit 启用每 host 令牌桶
*/
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cyberspacesec/gxx/v2/sdk"
)

func main() {
	startTime := time.Now()
	ctx := context.Background()

	options, err := sdk.NewFingerOptions()
	if err != nil {
		fmt.Printf("创建选项失败: %v\n", err)
		os.Exit(1)
	}

	target := "example.com"
	proxy := "http://127.0.0.1:8080"

	fmt.Printf("开始通过代理 %s 扫描目标: %s\n", proxy, target)
	fmt.Println("--------------------------------------------")

	engine, err := sdk.NewEngine(ctx,
		sdk.WithFingerOptions(options),
		sdk.WithProxy(proxy),
		sdk.WithTimeout(10*time.Second),
		sdk.WithRateLimit(20, 30),
	)
	if err != nil {
		fmt.Printf("初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer engine.Close()

	baseInfo, err := engine.GetBaseInfo(ctx, target)
	if err != nil {
		fmt.Printf("获取目标基本信息失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("URL: %s  状态码: %d  标题: %s\n", baseInfo.Target, baseInfo.StatusCode, baseInfo.Title)
	if baseInfo.Server != nil {
		fmt.Printf("服务器: %s\n", baseInfo.Server.ServerType)
	}

	result, err := engine.Scan(ctx, target)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		os.Exit(1)
	}

	if len(result.Matches) > 0 {
		fmt.Printf("\n匹配到 %d 个指纹:\n", len(result.Matches))
		for i, match := range result.Matches {
			fmt.Printf("  %d. %s\n", i+1, match.Info.Name)
		}
	} else {
		fmt.Println("\n未匹配到任何指纹")
	}

	if result.TechStack != nil && len(result.TechStack.WebServers) > 0 {
		fmt.Printf("Web服务器: %v\n", result.TechStack.WebServers)
	}

	fmt.Println("--------------------------------------------")
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
}
