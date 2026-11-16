/*
  - Package main
    @Author: zhizhuo
    @IDE：GoLand
    @File: main.go
    @Date: 2025/3/10 下午2:11*
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cyberspacesec/gxx/cmd/cli"
	"github.com/cyberspacesec/gxx/sdk"
	"github.com/cyberspacesec/gxx/utils/logger"

	"github.com/fatih/color"
)

const separator = "─────────────────────────────────────────────────────"

func main() {
	color.Green(cli.Banner)
	options, err := cli.NewCmdOptions()
	if err != nil {
		if errors.Is(err, cli.ErrHelp) {
			return
		}
		// 日志系统尚未初始化，直接写终端。
		color.Red("[ERROR] %s", err)
		os.Exit(1)
	}

	logLevel := 1 // INFO
	if options.Debug {
		logLevel = 4 // DEBUG
		color.Blue("DEBUG模式已开启")
	}
	logger.InitLogger("logs", 5, logLevel, options.NoFileLog)
	if options.NoFileLog {
		color.Blue("文件日志记录功能已禁用")
	}

	if options.Output == "" {
		options.Output = fmt.Sprintf("result_%d.txt", time.Now().Unix())
	}
	logger.Info("输出文件：%s", options.Output)
	if cli.OutputFormat(options.JSONOutput, options.Output) == sdk.FormatJSON {
		logger.Info("使用JSON格式输出结果")
	}

	startTime := time.Now()
	fmt.Println(color.CyanString(separator))
	fmt.Println(color.YellowString(" 开始扫描，请耐心等待..."))
	fmt.Println(color.CyanString(separator))

	// 输出文件与 socket 由 Runner 在扫描期间统一打开和关闭。
	if err := cli.Run(context.Background(), options); err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}

	fmt.Println(color.CyanString(separator))
	fmt.Printf("%s 耗时: %s\n",
		color.GreenString("扫描完成!"),
		color.YellowString("%s", time.Since(startTime).Round(time.Second)))
	fmt.Printf("结果已保存至: %s\n", color.CyanString(options.Output))
	fmt.Println(color.CyanString(separator))
	logger.Success("扫描完成")
}
