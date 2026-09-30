/*
  - Package common
    @Author: zhizhuo
    @IDE：GoLand
    @File: file.go
    @Date: 2025/2/20 下午3:37*
*/
package common

import (
	"os"
)

// Exists 判断文件是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		return os.IsExist(err)
	}
	return true
}
