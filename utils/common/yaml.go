/*
  - Package common
    @Author: zhizhuo
    @IDE：GoLand
    @File: yaml.go
    @Date: 2025/4/2 下午2:02*
*/
package common

import "strings"

// IsYamlFile 判断文件是否为YAML格式
func IsYamlFile(filename string) bool {
	return strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml")
}
