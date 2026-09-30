/*
  - Package types
    @Author: zhizhuo
    @IDE：GoLand
    @File: options.go
    @Date: 2025/3/10 下午2:39*
*/
package types

import (
	"github.com/projectdiscovery/goflags"
)

// YamlFingerType 指纹文件类型
type YamlFingerType struct {
	PocFile string // POC文件路径
	PocYaml string // 单个POC yaml文件
}

// CmdOptions 命令行选项结构体
type CmdOptions struct {
	Target      goflags.StringSlice // 测试目标
	TargetsFile string              // 测试目标文件
	Threads     int                 // 并发线程数
	Output      string              // 输出文件路径
	PocOptions  YamlFingerType      // POC yaml文件配置
	Timeout     int                 // 超时时间，默认5秒
	Proxy       string              // 代理地址
	Debug       bool                // 设置debug模式
	NoFileLog   bool                // 是否禁用文件日志，仅输出到控制台
	JSONOutput  bool                // 是否使用JSON格式输出结果
	SockOutput  string              // socket文件输出路径，启用后会以JSON格式输出到socket文件
	RuleThreads int                 // 指纹规则线程数
}
