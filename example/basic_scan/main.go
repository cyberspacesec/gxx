/*
basic_scan 演示如何用 sdk.Engine 对单目标进行完整指纹识别。

  - sdk.NewEngine + functional options 构造引擎
  - defer engine.Close() 释放资源
  - (*Engine).Scan 对单目标完整扫描
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

func main() {
	startTime := time.Now()
	ctx := context.Background()

	options, err := sdk.NewFingerOptions()
	if err != nil {
		fmt.Printf("创建选项失败: %v\n", err)
		os.Exit(1)
	}

	engine, err := sdk.NewEngine(ctx,
		sdk.WithFingerOptions(options),
		sdk.WithTimeout(5*time.Second),
		sdk.WithRuleConcurrency(200),
	)
	if err != nil {
		fmt.Printf("初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer engine.Close()

	targets := []string{"example.com", "github.com"}

	fmt.Println("开始扫描目标:", targets)
	fmt.Println("--------------------------------------------")

	for _, target := range targets {
		fmt.Printf("扫描目标: %s\n", target)

		result, err := engine.Scan(ctx, target)
		if err != nil {
			if errors.Is(err, sdk.ErrEmptyTarget) {
				fmt.Printf("跳过空目标\n")
				continue
			}
			fmt.Printf("扫描失败: %v\n", err)
			continue
		}

		fmt.Printf("URL: %s, 状态码: %d, 标题: %s\n", result.URL, result.StatusCode, result.Title)

		if result.ICP != "" {
			fmt.Printf("ICP: %s\n", result.ICP)
		}
		if len(result.Certs) > 0 {
			c := result.Certs[0]
			fmt.Printf("证书: 颁发者CN=%s, 主体CN=%s, 有效期=%s~%s\n",
				c.Issuer.CommonName, c.Subject.CommonName, c.NotBefore, c.NotAfter)
		}
		if result.Server != nil {
			fmt.Printf("服务器: %s\n", result.Server.ServerType)
		}

		if len(result.Matches) > 0 {
			fmt.Printf("\n匹配到 %d 个指纹:\n", len(result.Matches))
			for i, match := range result.Matches {
				fmt.Printf("  %d. %s\n", i+1, match.Info.Name)
			}
		} else {
			fmt.Println("\n未匹配到任何指纹")
		}

		if result.TechStack != nil {
			printTechStack(result.TechStack)
		}
		fmt.Println()
	}

	fmt.Println("--------------------------------------------")
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
	fmt.Printf("规则池统计: %+v\n", engine.PoolStats())
}

func printTechStack(ts *sdk.TechStack) {
	fmt.Println("\n技术栈信息:")
	if len(ts.WebServers) > 0 {
		fmt.Printf("  Web服务器: %v\n", ts.WebServers)
	}
	if len(ts.ProgrammingLanguages) > 0 {
		fmt.Printf("  编程语言: %v\n", ts.ProgrammingLanguages)
	}
	if len(ts.WebFrameworks) > 0 {
		fmt.Printf("  Web框架: %v\n", ts.WebFrameworks)
	}
	if len(ts.JavaScriptFrameworks) > 0 {
		fmt.Printf("  JS框架: %v\n", ts.JavaScriptFrameworks)
	}
	if len(ts.JavaScriptLibraries) > 0 {
		fmt.Printf("  JS库: %v\n", ts.JavaScriptLibraries)
	}
	if len(ts.Security) > 0 {
		fmt.Printf("  安全组件: %v\n", ts.Security)
	}
}
