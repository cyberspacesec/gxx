/*
  - Package types
    @Author: zhizhuo
    @IDE：GoLand
    @File: options.go
    @Date: 2025/3/10 下午2:39*
*/
package types

import "io/fs"

// YamlFingerType 指纹文件类型。FS 非空时从该文件系统的 Root 目录读取规则，
// 不能与 PocFile、PocYaml 同时使用。
type YamlFingerType struct {
	PocFile string // POC文件路径
	PocYaml string // 单个POC yaml文件
	FS      fs.FS  // 规则文件系统（如内存文件系统、embed.FS）
	Root    string // FS 中的规则目录，"" 与 "." 表示根目录
}
