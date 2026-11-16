/*
Package cli 命令行参数解析。

参数解析只依赖标准库 flag：SDK 与 CLI 共用的 types 包不再为一个字符串切片
引入第三方命令行框架及其传递依赖。
*/
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberspacesec/gxx/pkg/network"
)

// Options 命令行选项。
type Options struct {
	Targets     []string // -u：扫描目标
	TargetsFile string   // -f：目标文件，每行一个
	Threads     int      // -t：目标并发数
	RuleThreads int      // -rt：指纹规则并发数
	Output      string   // -o：输出文件
	JSONOutput  bool     // -json：强制 JSON Lines 输出
	SockOutput  string   // -sock：Unix socket 输出
	Proxy       string   // -proxy：代理地址
	RuleFile    string   // -p：单个规则文件
	RuleDir     string   // -pf：规则目录
	Timeout     int      // -timeout：请求超时（秒）
	Rate        int      // -rate：全部请求的总速率上限（次/秒），0 不限制
	RateMinute  int      // -rpm：全部请求的总速率上限（次/分钟），0 不限制
	HostRate    int      // -host-rate：单台主机的速率上限（次/秒），0 不限制
	Debug       bool     // -debug
	NoFileLog   bool     // -no-file-log
}

const (
	defaultThreads     = 5
	defaultRuleThreads = 200
	defaultTimeout     = 3
)

// ErrHelp 表示用户请求了帮助信息；用法已输出，调用方应以 0 退出。
var ErrHelp = flag.ErrHelp

// targetList 收集目标参数：可重复传入，也可用逗号分隔。
//
// 目标按原样保留，只去掉首尾空白和成对包裹的引号。URL 的路径与查询大小写
// 敏感，`#` 也可能是目标的一部分，不能做小写化或注释截断。
type targetList []string

func (t *targetList) String() string { return strings.Join(*t, ",") }

func (t *targetList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if len(item) >= 2 {
			if quote := item[0]; (quote == '"' || quote == '\'' || quote == '`') && item[len(item)-1] == quote {
				item = strings.TrimSpace(item[1 : len(item)-1])
			}
		}
		if item != "" {
			*t = append(*t, item)
		}
	}
	return nil
}

type flagUsage struct {
	names string
	usage string
}

type flagGroup struct {
	title string
	flags []flagUsage
}

// NewCmdOptions 解析进程命令行参数。
func NewCmdOptions() (*Options, error) {
	return ParseCmdOptions(os.Args[1:], os.Stdout)
}

// ParseCmdOptions 解析给定参数；用法与提示写入 out。
func ParseCmdOptions(args []string, out io.Writer) (*Options, error) {
	options := &Options{}
	var targets targetList
	flagSet := flag.NewFlagSet("gxx", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	flagSet.Var(&targets, "url", "")
	flagSet.Var(&targets, "u", "")
	flagSet.StringVar(&options.TargetsFile, "file", "", "")
	flagSet.StringVar(&options.TargetsFile, "f", "", "")
	flagSet.IntVar(&options.Threads, "threads", defaultThreads, "")
	flagSet.IntVar(&options.Threads, "t", defaultThreads, "")
	flagSet.IntVar(&options.RuleThreads, "rulethreads", defaultRuleThreads, "")
	flagSet.IntVar(&options.RuleThreads, "rt", defaultRuleThreads, "")

	flagSet.StringVar(&options.Output, "output", "", "")
	flagSet.StringVar(&options.Output, "o", "", "")
	flagSet.BoolVar(&options.JSONOutput, "json", false, "")
	flagSet.StringVar(&options.SockOutput, "sock", "", "")

	flagSet.StringVar(&options.Proxy, "proxy", "", "")
	flagSet.StringVar(&options.RuleFile, "p", "", "")
	flagSet.StringVar(&options.RuleDir, "pf", "", "")
	flagSet.IntVar(&options.Timeout, "timeout", defaultTimeout, "")
	flagSet.IntVar(&options.Rate, "rate", 0, "")
	flagSet.IntVar(&options.RateMinute, "rpm", 0, "")
	flagSet.IntVar(&options.HostRate, "host-rate", 0, "")
	flagSet.BoolVar(&options.Debug, "debug", false, "")
	flagSet.BoolVar(&options.NoFileLog, "no-file-log", false, "")

	groups := []flagGroup{
		{"目标", []flagUsage{
			{"-u, -url string[]", "要扫描的目标URL/主机（可重复或用逗号分隔）"},
			{"-f, -file string", "要扫描的目标URL/主机列表（每行一个）"},
			{"-t, -threads int", fmt.Sprintf("URL级并发线程数（默认 %d）", defaultThreads)},
			{"-rt, -rulethreads int", fmt.Sprintf("指纹规则并发线程数（默认 %d）", defaultRuleThreads)},
		}},
		{"输出", []flagUsage{
			{"-o, -output string", "输出文件路径，格式按扩展名识别（txt/csv/json）"},
			{"-json", "强制使用JSON Lines格式输出结果到文件"},
			{"-sock string", "socket文件输出路径，启用后以JSON格式输出到socket文件"},
		}},
		{"限速", []flagUsage{
			{"-rate int", "全部请求的总速率上限（次/秒，默认不限制）"},
			{"-rpm int", "全部请求的总速率上限（次/分钟，与 -rate 二选一）"},
			{"-host-rate int", "单台主机的速率上限（次/秒，默认不限制；同一主机的不同端口合并计算）"},
		}},
		{"调试", []flagUsage{
			{"-proxy string", "代理地址（单个），支持 http/https/socks5/socks5h，如 socks5://127.0.0.1:1080"},
			{"-p string", "测试单个的yaml文件"},
			{"-pf string", "测试指定目录下面所有的yaml文件"},
			{"-timeout int", fmt.Sprintf("所有请求的超时时间（秒，默认 %d）", defaultTimeout)},
			{"-debug", "开启debug模式"},
			{"-no-file-log", "禁用文件日志记录，仅输出到控制台"},
		}},
	}
	// flag 在 -h 与解析失败时都会先调用 Usage；这里不输出，由下面按错误类型
	// 决定：-h 打印一次完整用法，解析失败只返回错误与提示，避免用法重复刷屏。
	flagSet.Usage = func() {}

	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(out, groups)
			return options, ErrHelp
		}
		return options, fmt.Errorf("无法解析标志: %w（使用 -h 查看帮助）", err)
	}
	if extra := flagSet.Args(); len(extra) > 0 {
		return options, fmt.Errorf("无法识别的参数: %s", strings.Join(extra, " "))
	}
	options.Targets = targets

	if err := verifyOptions(options, out); err != nil {
		return options, err
	}
	return options, nil
}

func printUsage(out io.Writer, groups []flagGroup) {
	fmt.Fprintln(out, "GXX 是基于 YAML 规则的指纹识别引擎。")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "用法:")
	fmt.Fprintln(out, "  gxx [选项]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "选项:")
	width := 0
	for _, group := range groups {
		for _, item := range group.flags {
			width = max(width, len(item.names))
		}
	}
	for _, group := range groups {
		fmt.Fprintf(out, "%s:\n", group.title)
		for _, item := range group.flags {
			fmt.Fprintf(out, "   %-*s  %s\n", width, item.names, item.usage)
		}
		fmt.Fprintln(out)
	}
}

// verifyOptions 校验命令行选项，无效的并发与超时回退到默认值。
func verifyOptions(opt *Options, out io.Writer) error {
	if len(opt.Targets) == 0 && opt.TargetsFile == "" {
		return fmt.Errorf("必须设置 `-url` 或 `-file` 参数指定扫描目标")
	}

	// -json 强制 JSON 输出，此时不约束扩展名。
	if opt.Output != "" && !opt.JSONOutput {
		switch strings.ToLower(filepath.Ext(opt.Output)) {
		case ".txt", ".csv", ".json", ".jsonl":
		default:
			return fmt.Errorf("输出文件格式只支持 .txt、.csv、.json，或者使用 -json 参数强制JSON格式输出")
		}
	}

	if opt.SockOutput != "" && strings.ToLower(filepath.Ext(opt.SockOutput)) != ".sock" {
		return fmt.Errorf("socket输出文件必须使用.sock扩展名")
	}

	// 代理为单个 URL；支持 http/https/socks5/socks5h/socks4/socks4a。
	if opt.Proxy != "" {
		if _, err := network.ValidateProxyURL(opt.Proxy); err != nil {
			return err
		}
	}

	if opt.Rate < 0 || opt.RateMinute < 0 || opt.HostRate < 0 {
		return fmt.Errorf("限速参数不能为负数")
	}
	if opt.Rate > 0 && opt.RateMinute > 0 {
		return fmt.Errorf("-rate 与 -rpm 只能设置一个")
	}

	if opt.Threads <= 0 {
		fmt.Fprintf(out, "[-] 线程数无效，将使用默认值 %d\n", defaultThreads)
		opt.Threads = defaultThreads
	}
	if opt.RuleThreads <= 0 {
		fmt.Fprintf(out, "[-] 规则线程数无效，将使用默认值 %d\n", defaultRuleThreads)
		opt.RuleThreads = defaultRuleThreads
	}
	if opt.Timeout <= 0 {
		fmt.Fprintf(out, "[-] 超时时间无效，将使用默认值 %d 秒\n", defaultTimeout)
		opt.Timeout = defaultTimeout
	}
	return nil
}
