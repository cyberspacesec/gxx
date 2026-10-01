/*
wappalyzer_scan 演示仅技术栈识别（不跑指纹匹配）。

  - 同一个 Engine 跨多目标复用
  - GetBaseInfo（含 TechStack 字段）与 WappalyzerScan（仅 TechStack）取值方式
*/
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cyberspacesec/gxx/v2/sdk"
)

func main() {
	startTime := time.Now()
	ctx := context.Background()

	engine, err := sdk.NewEngine(ctx,
		sdk.WithTimeout(10*time.Second),
	)
	if err != nil {
		fmt.Printf("初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer engine.Close()

	targets := []string{"https://www.baidu.com", "https://example.com"}

	for i, target := range targets {
		if i > 0 {
			fmt.Println("\n" + strings.Repeat("=", 50) + "\n")
		}

		fmt.Printf("开始分析目标: %s\n", target)
		fmt.Println("--------------------------------------------")

		baseInfo, err := engine.GetBaseInfo(ctx, target)
		if err != nil {
			fmt.Printf("获取基本信息失败: %v\n", err)
			continue
		}

		fmt.Printf("URL: %s  状态码: %d  标题: %s\n", baseInfo.Target, baseInfo.StatusCode, baseInfo.Title)
		if baseInfo.Server != nil {
			fmt.Printf("服务器: %s %s\n", baseInfo.Server.ServerType, baseInfo.Server.Version)
		}

		if baseInfo.TechStack != nil {
			fmt.Println("\n技术栈信息（来自 GetBaseInfo）:")
			printTechStack(baseInfo.TechStack)
		}

		fmt.Println("\n通过 WappalyzerScan API:")
		ts, err := engine.WappalyzerScan(ctx, target)
		if err != nil {
			fmt.Printf("技术栈分析失败: %v\n", err)
			continue
		}
		printTechStack(ts)
	}

	fmt.Println("--------------------------------------------")
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
}

func printTechStack(ts *sdk.TechStack) {
	printCategory := func(name string, items []string) {
		if len(items) > 0 {
			fmt.Printf("  %s: %v\n", name, items)
		}
	}
	printCategory("Web服务器", ts.WebServers)
	printCategory("编程语言", ts.ProgrammingLanguages)
	printCategory("Web框架", ts.WebFrameworks)
	printCategory("JS框架", ts.JavaScriptFrameworks)
	printCategory("JS库", ts.JavaScriptLibraries)
	printCategory("安全组件", ts.Security)
	printCategory("缓存", ts.Caching)
	printCategory("反向代理", ts.ReverseProxies)
	printCategory("静态站点", ts.StaticSiteGenerator)
	printCategory("其他", ts.Other)
}
