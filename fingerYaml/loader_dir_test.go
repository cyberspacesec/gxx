//go:build !embed

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// S1：磁盘指纹库只在工作目录与二进制所在目录查找，不再逐级向上。
// 工作目录的祖先目录中存在无关的 fingerYaml/ 不应被静默采用。
func TestFindFingerYamlDirDoesNotWalkUp(t *testing.T) {
	parent := t.TempDir()
	// 祖先目录放一个无关的 fingerYaml/
	if err := os.MkdirAll(filepath.Join(parent, "fingerYaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "a", "b")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	// 祖先目录的 fingerYaml/ 不含内置库子目录结构，不应被采用。
	if dir, err := findFingerYamlDir(); err == nil {
		t.Fatalf("不应采用无内置库结构的祖先 fingerYaml/，却返回了 %s", dir)
	}

	// 具备内置库结构（含已知子目录）的 fingerYaml/ 才会被采用。
	lib := filepath.Join(parent, "fingerYaml")
	for _, sub := range []string{"fingerprints", "fingers"} {
		if err := os.MkdirAll(filepath.Join(lib, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := findFingerYamlDir()
	if err != nil || dir != lib {
		t.Fatalf("应采用具备内置库结构的祖先 fingerYaml/，得到 dir=%s err=%v", dir, err)
	}
}
