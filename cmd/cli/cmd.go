/*
Package cli 是 gxx 的命令行前端：参数解析、目标加载、进度与终端显示。

识别与结果输出全部由 SDK 完成，命令行的 JSON / CSV / TXT / Socket 输出与 SDK
的 Writer 是同一套实现和同一种数据结构。
*/
package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/fatih/color"
)

// OutputFormat 确定输出格式：-json 优先，其余按扩展名识别，默认 txt。
func OutputFormat(jsonOutput bool, outputPath string) sdk.OutputFormat {
	if jsonOutput {
		return sdk.FormatJSON
	}
	switch strings.ToLower(filepath.Ext(outputPath)) {
	case ".csv":
		return sdk.FormatCSV
	case ".json", ".jsonl":
		return sdk.FormatJSON
	}
	return sdk.FormatTXT
}

// Run 执行批量扫描；初始化或扫描失败时返回错误，由入口决定退出码。
func Run(ctx context.Context, options *Options) error {
	targets, total, err := LoadTargets(options)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("未找到有效的目标URL")
	}
	logger.Info("原始目标数量：%d个，重复目标数量：%d个，去重后目标数量：%d个", total, total-len(targets), len(targets))

	var limits []sdk.Option
	switch {
	case options.Rate > 0:
		limits = append(limits, sdk.WithGlobalRateLimit(float64(options.Rate), options.Rate))
	case options.RateMinute > 0:
		limits = append(limits, sdk.WithGlobalRatePerMinute(options.RateMinute))
	}
	if options.HostRate > 0 {
		limits = append(limits, sdk.WithRateLimit(float64(options.HostRate), options.HostRate), sdk.WithRateLimitPerPort(options.HostRatePerPort))
	}
	engine, err := sdk.NewEngine(ctx, append(limits,
		sdk.WithFingerOptions(sdk.FingerOptions{PocFile: options.RuleDir, PocYaml: options.RuleFile}),
		sdk.WithProxy(options.Proxy),
		sdk.WithTimeout(time.Duration(options.Timeout)*time.Second),
		sdk.WithURLConcurrency(options.Threads),
		sdk.WithRuleConcurrency(options.RuleThreads),
		sdk.WithMemoryMonitor(true),
		sdk.WithDebug(options.Debug),
	)...)
	if err != nil {
		return fmt.Errorf("初始化运行时失败: %w", err)
	}
	defer func() { _ = engine.Close() }()

	var writers []sdk.Writer
	if options.Output != "" {
		writer, err := sdk.NewFileWriter(options.Output, OutputFormat(options.JSONOutput, options.Output))
		if err != nil {
			return fmt.Errorf("初始化输出文件失败: %w", err)
		}
		writers = append(writers, writer)
	}
	if options.SockOutput != "" {
		writer, err := sdk.NewSockWriter(options.SockOutput)
		if err != nil {
			return fmt.Errorf("初始化socket输出文件失败: %w", err)
		}
		writers = append(writers, writer)
		logger.Info("Socket输出文件：%s", options.SockOutput)
	}
	// 关闭时排空异步写入队列，结果在 Run 返回前落盘。
	writer := sdk.NewMultiWriter(writers...)
	defer func() { _ = writer.Close() }()

	logger.Info("开始扫描 %d 个目标，URL并发=%d 规则并发=%d ...", len(targets), options.Threads, options.RuleThreads)
	screen := newConsole(len(targets))
	start := time.Now()
	matched := 0
	var statsMu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, options.Threads)
dispatch:
	for _, target := range targets {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break dispatch
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			result, err := engine.Scan(ctx, target)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// 不可达的目标同样写入结果，便于和输入逐条对照。
				logger.Error("处理目标 %s 失败: %v", target, err)
				result = &sdk.TargetResult{URL: target, Matches: []sdk.FingerMatch{}}
			}
			if err := writer.Write(ctx, result); err != nil {
				logger.Error("写入目标 %s 的结果失败: %v", target, err)
			}
			if len(result.Matches) > 0 {
				statsMu.Lock()
				matched++
				statsMu.Unlock()
			}
			screen.report(resultLine(result))
		}()
	}
	wg.Wait()
	screen.close()

	elapsed := time.Since(start)
	fmt.Printf("\n指纹识别 100%% [==================================================] (%d/%d, %.2f it/s)\n",
		len(targets), len(targets), float64(len(targets))/elapsed.Seconds())
	stats := engine.PoolStats()
	logger.Info("规则池统计 - 总任务: %d, 已完成: %d, 失败: %d", stats.TotalTasks, stats.CompletedTasks, stats.FailedTasks)
	fmt.Println(color.CyanString(separator))
	fmt.Printf("扫描统计: 目标总数 %d, 匹配成功 %d, 匹配失败 %d\n", len(targets), matched, len(targets)-matched)
	return ctx.Err()
}

const separator = "─────────────────────────────────────────────────────"
