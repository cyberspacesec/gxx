/*
api_scan_baidu 演示 GetBaseInfo + Scan 的组合用法。

  - GetBaseInfo 仅获取目标基础信息（不跑指纹）
  - Scan 执行完整指纹识别
  - 使用 errors.Is + sentinel error 处理错误分支
*/
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cyberspacesec/gxx/v2/sdk"
)

func main() {
	ctx := context.Background()

	options, err := sdk.NewFingerOptions()
	if err != nil {
		log.Fatalf("创建选项错误: %v", err)
	}

	fmt.Println("初始化引擎...")
	startTime := time.Now()
	engine, err := sdk.NewEngine(ctx,
		sdk.WithFingerOptions(options),
		sdk.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("初始化引擎错误: %v", err)
	}
	defer engine.Close()
	fmt.Printf("初始化完成，耗时: %s\n", time.Since(startTime))

	target := "https://www.baidu.com"

	fmt.Printf("\n开始获取目标基础信息: %s\n", target)
	baseInfo, err := engine.GetBaseInfo(ctx, target)
	if err != nil {
		switch {
		case errors.Is(err, sdk.ErrEngineClosed):
			fmt.Println("引擎已关闭")
		default:
			fmt.Printf("获取基础信息失败: %v\n", err)
		}
	} else {
		fmt.Printf("状态码: %d\n", baseInfo.StatusCode)
		fmt.Printf("标题: %s\n", baseInfo.Title)
		if baseInfo.Server != nil {
			fmt.Printf("服务器: %s\n", baseInfo.Server.ServerType)
		}
		if baseInfo.ICP != "" {
			fmt.Printf("ICP: %s\n", baseInfo.ICP)
		}
		if len(baseInfo.Certs) > 0 {
			c := baseInfo.Certs[0]
			fmt.Printf("证书: 颁发者CN=%s, 主体CN=%s\n", c.Issuer.CommonName, c.Subject.CommonName)
		}
		if baseInfo.TechStack != nil {
			jsonData, _ := json.MarshalIndent(baseInfo.TechStack, "", "  ")
			fmt.Printf("技术栈:\n%s\n", string(jsonData))
		}
	}

	fmt.Printf("\n开始进行指纹识别: %s\n", target)
	startTime = time.Now()
	res, err := engine.Scan(ctx, target)
	if err != nil {
		fmt.Printf("指纹识别失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("指纹识别完成，耗时: %s\n", time.Since(startTime))

	fmt.Printf("\nURL: %s  状态码: %d  标题: %s\n", res.URL, res.StatusCode, res.Title)
	if len(res.Matches) > 0 {
		fmt.Printf("\n匹配的指纹 (%d个):\n", len(res.Matches))
		for i, match := range res.Matches {
			fmt.Printf("  %d. %s (ID: %s)\n", i+1, match.Info.Name, match.Info.ID)
		}
	} else {
		fmt.Println("\n未匹配到任何指纹")
	}
}
