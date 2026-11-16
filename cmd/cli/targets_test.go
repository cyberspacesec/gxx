package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberspacesec/gxx/sdk"
)

func TestLoadTargetsKeepsOrderAndDedupesByEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "\ufeffhttp://b.example\r\n# 注释\n\nhttps://b.example\nhttp://B.example:80/\nhttp://a.example/x?y=1\nhttp://a.example/x?y=2\nc.example:8080\nC.example:8080\nhttp://b.example/\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, total, err := LoadTargets(&Options{TargetsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	// http 与 https 是两个资产；同一入口的不同写法只保留第一个；顺序与输入一致。
	want := []string{"http://b.example", "https://b.example", "http://a.example/x?y=1", "http://a.example/x?y=2", "c.example:8080"}
	if !slices.Equal(targets, want) || total != 8 {
		t.Fatalf("targets=%q total=%d", targets, total)
	}
	targets, _, _ = LoadTargets(&Options{Targets: []string{"http://x", "http://x/"}, TargetsFile: path})
	if !slices.Equal(targets, []string{"http://x"}) {
		t.Fatalf("命令行目标应优先于文件: %q", targets)
	}
	if _, _, err := LoadTargets(&Options{TargetsFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("目标文件不存在应返回错误")
	}
}

func TestOutputFormat(t *testing.T) {
	for path, want := range map[string]sdk.OutputFormat{"a.txt": sdk.FormatTXT, "a.CSV": sdk.FormatCSV, "a.json": sdk.FormatJSON, "a.jsonl": sdk.FormatJSON, "a": sdk.FormatTXT} {
		if got := OutputFormat(false, path); got != want {
			t.Errorf("%s: %s", path, got)
		}
	}
	if OutputFormat(true, "a.txt") != sdk.FormatJSON {
		t.Error("-json 应优先于扩展名")
	}
}

func TestFailureReasonIsOneLine(t *testing.T) {
	err := fmt.Errorf("scan target %q: %w", "https://a.com", errors.Join(sdk.ErrScanFailed, errors.New(`发送请求失败: Get "https://a.com": context deadline exceeded`)))
	got := failureReason(err)
	if strings.ContainsAny(got, "\n") || strings.Contains(got, "sdk: scan failed") || !strings.HasSuffix(got, "context deadline exceeded") {
		t.Fatalf("失败原因应为一行且保留具体原因: %q", got)
	}
}
