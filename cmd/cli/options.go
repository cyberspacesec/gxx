/*
  - Package cmd
    @Author: zhizhuo
    @IDE：GoLand
    @File: options.go
    @Date: 2025/2/20 下午3:39*
*/
package cli

import (
	"fmt"
	"github.com/cyberspacesec/gxx/types"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/goflags"
)

// NewCmdOptions 创建并解析命令行选项
func NewCmdOptions() (*types.CmdOptions, error) {
	options := &types.CmdOptions{}
	flagSet := goflags.NewFlagSet()
	flagSet.CreateGroup("input", "目标",
		flagSet.StringSliceVarP(&options.Target, "url", "u", nil, "要扫描的目标URL/主机", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.TargetsFile, "file", "f", "", "要扫描的目标URL/主机列表（每行一个）"),
		flagSet.IntVarP(&options.Threads, "threads", "t", 5, "URL级并发线程数"),
		flagSet.IntVarP(&options.RuleThreads, "rulethreads", "rt", 200, "指纹规则并发线程数"),
	)
	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&options.Output, "output", "o", "", "输出文件路径（支持txt/csv格式）"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "使用JSON格式输出结果到文件（默认关闭）"),
		flagSet.StringVar(&options.SockOutput, "sock", "", "socket文件输出路径，启用后以JSON格式输出到socket文件"),
	)
	flagSet.CreateGroup("debug", "调试",
		flagSet.StringVar(&options.Proxy, "proxy", "", "要使用的http/socks5代理列表（逗号分隔或文件输入）"),
		flagSet.StringVar(&options.PocOptions.PocYaml, "p", "", "测试单个的yaml文件"),
		flagSet.StringVar(&options.PocOptions.PocFile, "pf", "", "测试指定目录下面所有的yaml文件"),
		flagSet.IntVar(&options.Timeout, "timeout", 3, "所有请求的超时时间（秒），默认3秒"),
		flagSet.BoolVar(&options.Debug, "debug", false, "是否开启debug模式，默认关闭"),
		flagSet.BoolVar(&options.NoFileLog, "no-file-log", false, "禁用文件日志记录，仅输出到控制台"),
	)

	// 实例化操作
	if err := flagSet.Parse(); err != nil {
		return options, fmt.Errorf("无法解析标志: %s", err)
	}
	// 验证必参数是否传入
	if err := verifyOptions(options); err != nil {
		return options, err
	}

	return options, nil
}

// verifyOptions 验证命令行选项
func verifyOptions(opt *types.CmdOptions) error {
	// 使用反射自动序列化命令行选项用于调试
	//optionsStr := fmt.Sprintf("%+v", *opt)
	//fmt.Println("命令行选项：", optionsStr)

	// 验证目标输入
	if len(opt.Target) == 0 && opt.TargetsFile == "" {
		return fmt.Errorf("必须设置 `-url` 或 `-file` 参数指定扫描目标")
	}

	// 验证输出文件格式
	if opt.Output != "" && !opt.JSONOutput { // 如果启用了JSON格式输出，则不检查文件扩展名
		ext := strings.ToLower(filepath.Ext(opt.Output))
		if ext != ".txt" && ext != ".csv" {
			return fmt.Errorf("输出文件格式只支持 .txt 或 .csv，或者使用 -json 参数启用JSON格式输出")
		}
	}

	// 验证socket文件扩展名
	if opt.SockOutput != "" {
		ext := strings.ToLower(filepath.Ext(opt.SockOutput))
		if ext != ".sock" {
			return fmt.Errorf("socket输出文件必须使用.sock扩展名")
		}
	}

	// 验证线程数（<=0 则回退到默认配置）
	if opt.Threads <= 0 {
		fmt.Println("[-] 线程数无效，将使用默认值 5")
		opt.Threads = 5
	}
	if opt.RuleThreads <= 0 {
		fmt.Println("[-] 规则线程数无效，将使用默认值 200")
		opt.RuleThreads = 200
	}

	// 验证超时时间
	if opt.Timeout <= 0 {
		fmt.Println("[-] 超时时间无效，将使用默认值 3 秒")
		opt.Timeout = 3
	}

	return nil
}
