//go:build !embed

package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	finger2 "github.com/cyberspacesec/gxx/pkg/finger"
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

	// 具备内置库结构（含产品分类子目录）的 fingerYaml/ 才会被采用。
	lib := filepath.Join(parent, "fingerYaml")
	for _, sub := range []string{"application", "web-server"} {
		if err := os.MkdirAll(filepath.Join(lib, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := findFingerYamlDir()
	if err != nil || dir != lib {
		t.Fatalf("应采用具备内置库结构的祖先 fingerYaml/，得到 dir=%s err=%v", dir, err)
	}
}

// 加载磁盘规则库时同样检查同一产品的声明一致，不一致即加载失败。
func TestDiskLibraryRejectsInconsistentProducts(t *testing.T) {
	root := t.TempDir()
	rule := func(id, name string) string {
		return "id: " + id + "\ninfo:\n  name: " + id + "\n  product:\n    id: acme.portal\n    name: " + name +
			"\n    category: application\n    identity: product\n    assurance: inferred\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: 'true'\nexpression: r0()\n"
	}
	files := map[string]string{"application/acme-portal.yaml": rule("acme-portal", "Portal"), "cms/acme-portal-cms.yaml": rule("acme-portal-cms", "Portal")}
	for name, content := range files {
		path := filepath.Join(root, "fingerYaml", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	if rules, err := GetFingerYaml(); err != nil || len(rules) != 2 {
		t.Fatalf("声明一致时应加载成功: %d %v", len(rules), err)
	}
	if err := os.WriteFile(filepath.Join(root, "fingerYaml", "cms", "acme-portal-cms.yaml"), []byte(rule("acme-portal-cms", "Other")), 0o600); err != nil {
		t.Fatal(err)
	}
	var conflict *finger2.ProductConflictError
	if _, err := GetFingerYaml(); !errors.As(err, &conflict) || conflict.Field != "name" {
		t.Fatalf("产品声明不一致应加载失败: %v", err)
	}
}
