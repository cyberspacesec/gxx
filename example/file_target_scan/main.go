/*
file_target_scan 演示从文件读取目标列表批量扫描。

  - (*Engine).ScanCallback 实时处理每个目标的结果
  - WithURLConcurrency 控制并发数
*/
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	exampleDir, _ := os.Getwd()
	targetsFile := filepath.Join(exampleDir, "targets.txt")
	createExampleTargetFile(targetsFile)

	engine, err := sdk.NewEngine(ctx,
		sdk.WithFingerOptions(options),
		sdk.WithTimeout(5*time.Second),
		sdk.WithURLConcurrency(20),
		sdk.WithRuleConcurrency(200),
	)
	if err != nil {
		fmt.Printf("初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer engine.Close()

	targets, err := readTargetsFromFile(targetsFile)
	if err != nil {
		fmt.Printf("读取目标文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("从文件中读取到 %d 个目标\n", len(targets))
	fmt.Println("--------------------------------------------")

	results := make(map[string]*sdk.TargetResult, len(targets))
	var mu sync.Mutex

	cb := func(r *sdk.TargetResult) bool {
		mu.Lock()
		results[r.URL] = r
		mu.Unlock()
		fmt.Printf("✓ %s [%d] %s (匹配 %d 条指纹)\n", r.URL, r.StatusCode, r.Title, len(r.Matches))
		return true
	}

	if err := engine.ScanCallback(ctx, targets, cb); err != nil {
		fmt.Printf("批量扫描失败: %v\n", err)
	}

	fmt.Println("\n扫描结果:")
	fmt.Printf("总共扫描: %d 个目标, 成功: %d 个\n", len(targets), len(results))
	for target, result := range results {
		fmt.Printf("\n目标: %s  状态码: %d  标题: %s\n", target, result.StatusCode, result.Title)
		if result.Server != nil {
			fmt.Printf("  服务器: %s\n", result.Server.ServerType)
		}
		if len(result.Matches) > 0 {
			fmt.Printf("  匹配指纹: %d 个\n", len(result.Matches))
			for i, m := range result.Matches {
				if i >= 3 {
					fmt.Printf("    ...（还有 %d 个）\n", len(result.Matches)-3)
					break
				}
				fmt.Printf("    %d. %s\n", i+1, m.Info.Name)
			}
		}
	}

	fmt.Println("--------------------------------------------")
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
	fmt.Printf("规则池统计: %+v\n", engine.PoolStats())
}

func createExampleTargetFile(filePath string) {
	if _, err := os.Stat(filePath); err == nil {
		return
	}
	targets := []string{"example.com", "github.com", "httpbin.org"}
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("创建目标文件失败: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()
	for _, t := range targets {
		_, _ = file.WriteString(t + "\n")
	}
	fmt.Println("已创建示例目标文件:", filePath)
}

func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t != "" {
			targets = append(targets, t)
		}
	}
	return targets, scanner.Err()
}
