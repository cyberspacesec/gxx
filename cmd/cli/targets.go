package cli

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/cyberspacesec/gxx/pkg/network"
)

// LoadTargets 返回去重后的扫描目标，保持输入顺序。
//
// 命令行目标优先于目标文件。文件每行一个目标，空行与 # 开头的注释行被跳过。
// 去重按资产入口判断：协议、主机、端口相同且路径与查询串相同的写法只保留第一个
// （http://a.com 与 http://A.com:80/ 是同一个入口；http 与 https 是不同的资产）。
func LoadTargets(options *Options) ([]string, int, error) {
	raw := options.Targets
	if len(raw) == 0 && options.TargetsFile != "" {
		file, err := os.Open(options.TargetsFile)
		if err != nil {
			return nil, 0, fmt.Errorf("读取目标文件失败: %w", err)
		}
		defer func() { _ = file.Close() }()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			raw = append(raw, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, 0, fmt.Errorf("读取目标文件失败: %w", err)
		}
	}
	seen := make(map[string]struct{}, len(raw))
	targets := make([]string, 0, len(raw))
	total := 0
	for _, line := range raw {
		target := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if target == "" || strings.HasPrefix(target, "#") {
			continue
		}
		total++
		key := targetKey(target)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}
	return targets, total, nil
}

// targetKey 返回用于去重的入口标识；无法解析的目标按原文比较。
func targetKey(target string) string {
	if !strings.Contains(target, "://") {
		// 未带协议的目标由扫描时探测协议，只规范化主机大小写。
		host, rest, _ := strings.Cut(target, "/")
		return strings.ToLower(host) + "/" + rest
	}
	u, err := url.Parse(target)
	origin := network.Origin(u)
	if err != nil || origin == "" {
		return target
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return origin + path + "?" + u.RawQuery
}
