package output

import (
	"fmt"
	"strings"
)

// formatStringArray 将字符串数组格式化为字符串
func formatStringArray(arr []string) string {
	if arr == nil || len(arr) == 0 {
		return "-"
	}
	return fmt.Sprintf("[%s]", strings.Join(arr, "，"))
}
