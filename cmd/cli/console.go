package cli

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/progress"
	"github.com/schollz/progressbar/v3"
)

// resultLine 把一个目标的识别结果格式化为终端上的一行。
func resultLine(result *sdk.TargetResult) string {
	var b strings.Builder
	b.WriteString("URL：")
	b.WriteString(result.URL)
	if result.StatusCode > 0 {
		fmt.Fprintf(&b, " （%d）", result.StatusCode)
	}
	if result.FinalURL != "" && result.FinalURL != result.URL {
		b.WriteString("  最终页面：")
		b.WriteString(result.FinalURL)
	}
	if result.RedirectTo != "" {
		b.WriteString("  页面跳转（未跟随）：")
		b.WriteString(result.RedirectTo)
	}
	b.WriteString("  标题：")
	b.WriteString(result.Title)
	if result.Server != nil && result.Server.OriginalServer != "" {
		b.WriteString("  Server：")
		b.WriteString(result.Server.OriginalServer)
	}
	if tech := result.TechStack; tech != nil {
		for _, group := range []struct {
			label  string
			values []string
		}{
			{"Web服务器", tech.WebServers}, {"编程语言", tech.ProgrammingLanguages}, {"Web框架", tech.WebFrameworks},
			{"CMS", tech.CMS}, {"数据库", tech.Databases}, {"JS组件", append(append([]string{}, tech.JavaScriptFrameworks...), tech.JavaScriptLibraries...)},
		} {
			if len(group.values) > 0 {
				fmt.Fprintf(&b, "  %s：[%s]", group.label, strings.Join(group.values, ", "))
			}
		}
	}
	if icp := strings.TrimSpace(result.ICP); icp != "" {
		b.WriteString("  备案号：")
		b.WriteString(icp)
	}
	if len(result.Matches) == 0 {
		b.WriteString("  匹配结果：\033[31m未匹配\033[0m")
		return b.String()
	}
	names := make([]string, 0, len(result.Matches))
	for _, match := range result.Matches {
		name := match.Info.Name
		if match.ProductVersion != "" {
			name += " " + match.ProductVersion
		}
		names = append(names, name)
	}
	fmt.Fprintf(&b, "  指纹：[%s]  匹配结果：\033[32m成功\033[0m", strings.Join(names, "，"))
	return b.String()
}

// console 串行化终端输出：结果行与进度条共用一个终端，不能交错写入。
type console struct {
	mu       sync.Mutex
	bar      *progressbar.ProgressBar
	stop     chan struct{}
	finished sync.WaitGroup
}

func newConsole(total int) *console {
	c := &console{bar: progress.New(total, "指纹识别"), stop: make(chan struct{})}
	c.finished.Add(1)
	go func() {
		defer c.finished.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				c.mu.Lock()
				_ = c.bar.RenderBlank()
				c.mu.Unlock()
			}
		}
	}()
	return c
}

// report 输出一个目标的结果行并推进进度条。
func (c *console) report(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Print("\033[2K\r")
	fmt.Println(line)
	if err := c.bar.Add(1); err != nil {
		logger.Debug("更新进度条出错: %v", err)
	}
}

func (c *console) close() {
	close(c.stop)
	c.finished.Wait()
	c.mu.Lock()
	_ = c.bar.Finish()
	c.mu.Unlock()
}
