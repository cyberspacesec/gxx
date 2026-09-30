/*
  - Package cmd
    @Author: zhizhuo
    @IDE：GoLand
    @File: banner.go
    @Date: 2025/2/20 下午3:39*
*/
package cli

import (
	"strings"
	"time"
)

// 默认版本信息 - 使用 var 使其可以通过 ldflags 修改
var defaultVersion = "1.1.9"
var defaultAuthor = "zhizhuo"
var defaultBuildDate = "BUILD_TIME"

// Banner 程序启动时显示的横幅
var Banner = strings.TrimSpace(`
 _______  ___  _
/  __\  \/\  \//
| |  _\  / \  / 
| |_///  \ /  \ 
\____/__/\/__/\\`) + "\n\n\t\tVersion: " + defaultVersion +
	"\n\t\tAuthor: " + defaultAuthor +
	"\n\t\tBuild: " + getBuildDate()

// getBuildDate 获取构建日期
func getBuildDate() string {
	// 如果是默认的 BUILD_TIME 或为空，使用当前日期
	if defaultBuildDate == "BUILD_TIME" {
		return time.Now().Format("2006-01-02")
	}

	return defaultBuildDate
}
