// Package progress 提供终端进度条，适配窄窗口。
package progress

import (
	"os"

	"github.com/schollz/progressbar/v3"
)

// New 创建对小窗口友好的单行进度条。
func New(total int, description string) *progressbar.ProgressBar {
	if description == "" {
		description = "进度"
	}
	return progressbar.NewOptions64(
		int64(total),
		progressbar.OptionFullWidth(),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionClearOnFinish(),
	)
}
