/*
output_writer 演示 sdk v3 新增的 Writer 抽象。

  - WithOutputFile 把结果写入本地 JSON Lines 文件
  - WithWriter 同时注入自定义 Writer（这里实现简易计数器）

Writer 与 Scan 回调可以并存：Engine 在每完成一个目标后会先派发到所有 Writer，
再触发 ScanCallback 的用户回调。
*/
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// countingWriter 累计目标数量，演示如何实现 sdk.Writer 接口。
type countingWriter struct {
	count atomic.Int64
}

// Write 实现 sdk.Writer：每个完成扫描的目标都会被传入。
func (c *countingWriter) Write(_ context.Context, _ *sdk.TargetResult) error {
	c.count.Add(1)
	return nil
}

// Close 实现 sdk.Writer：演示用 Writer 无需释放资源。
func (c *countingWriter) Close() error { return nil }

func main() {
	startTime := time.Now()
	ctx := context.Background()

	options, err := sdk.NewFingerOptions()
	if err != nil {
		fmt.Printf("创建选项失败: %v\n", err)
		os.Exit(1)
	}

	outDir, _ := os.Getwd()
	outPath := filepath.Join(outDir, "results.json")

	counter := &countingWriter{}
	engine, err := sdk.NewEngine(ctx,
		sdk.WithFingerOptions(options),
		sdk.WithTimeout(5*time.Second),
		sdk.WithURLConcurrency(5),
		sdk.WithRuleConcurrency(100),
		sdk.WithOutputFile(outPath, sdk.FormatJSON),
		sdk.WithWriter(counter),
	)
	if err != nil {
		fmt.Printf("初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer engine.Close()

	targets := []string{"https://example.com", "https://www.baidu.com"}
	fmt.Println("Writer 演示：扫描结果将写入", outPath)
	fmt.Println("--------------------------------------------")

	for _, target := range targets {
		result, err := engine.Scan(ctx, target)
		if err != nil {
			fmt.Printf("扫描 %s 失败: %v\n", target, err)
			continue
		}
		fmt.Printf("✓ %s [%d] %s (匹配 %d 条指纹)\n",
			result.URL, result.StatusCode, result.Title, len(result.Matches))
	}

	fmt.Println("--------------------------------------------")
	fmt.Printf("countingWriter 共收到 %d 条结果\n", counter.count.Load())
	fmt.Printf("结果文件: %s\n", outPath)
	fmt.Printf("总耗时: %s\n", time.Since(startTime))
}
