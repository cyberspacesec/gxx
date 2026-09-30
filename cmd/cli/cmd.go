/*
Package cli 命令行入口。

CLI 通过 runner.NewRunner 构造完整运行时实例，调用 Run 执行批量扫描，
退出时 defer Close 释放规则池 / 缓存 / 监控器等资源。
*/
package cli

import (
	"context"
	"time"

	"github.com/cyberspacesec/gxx/pkg/runner"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/output"
)

// Run 执行批量扫描。
func Run(options *types.CmdOptions) {
	cfg := runner.ScanConfig{
		Proxy:              options.Proxy,
		Timeout:            time.Duration(options.Timeout) * time.Second,
		URLWorkerCount:     options.Threads,
		FingerWorkerCount:  options.RuleThreads,
		OutputFormat:       output.GetOutputFormat(options.JSONOutput, options.Output),
		OutputFile:         options.Output,
		SockOutputFile:     options.SockOutput,
		EnableMonitor:      true,
		InsecureSkipVerify: true,
		Debug:              options.Debug,
	}

	r, err := runner.NewRunner(cfg, options.PocOptions)
	if err != nil {
		logger.Error("初始化运行时失败: %v", err)
		return
	}
	defer func() { _ = r.Close() }()

	if err := r.Run(context.Background(), options); err != nil {
		logger.Error("扫描出错: %v", err)
	}
}
