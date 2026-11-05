package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
)

// S6：显式指定的目录/文件未解析出任何规则时必须报错，而非静默加载 0 条规则。
func TestLoadEmptyDirectoryErrors(t *testing.T) {
	store := NewFingerStore(logger.Discard())
	emptyDir := t.TempDir()
	if err := store.Load(types.YamlFingerType{PocFile: emptyDir}); err == nil {
		t.Fatal("加载空目录应报错")
	}
	// 非 yaml 文件目录同样视为空。
	if err := os.WriteFile(filepath.Join(emptyDir, "readme.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(types.YamlFingerType{PocFile: emptyDir}); err == nil {
		t.Fatal("仅含非 yaml 文件的目录应报错")
	}
	// 有效目录应成功。
	if err := os.WriteFile(filepath.Join(emptyDir, "r.yaml"), []byte("id: t\ninfo:\n  name: t\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: 'true'\nexpression: r0()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(types.YamlFingerType{PocFile: emptyDir}); err != nil {
		t.Fatalf("有效目录不应报错: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("规则数=%d 期望 1", store.Count())
	}
}
