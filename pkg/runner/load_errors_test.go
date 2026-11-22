package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

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

// 执行清单先派发需要自己发请求的规则，同类之间保持规则库顺序；规则元数据仍按规则库顺序。
func TestExecutionPlanDispatchesRequestRulesFirst(t *testing.T) {
	rule := func(id, path string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("id: " + id + "\ninfo:\n  name: " + id + "\nrules:\n  r0:\n    request:\n      method: GET\n      path: " + path + "\n    expression: response.status == 200\nexpression: r0()\n")}
	}
	files := fstest.MapFS{"a.yaml": rule("a-root", "/"), "b.yaml": rule("b-login", "/login"), "c.yaml": rule("c-root", "/"), "d.yaml": rule("d-admin", "/admin")}
	store := NewFingerStore(logger.Discard())
	if err := store.Load(types.YamlFingerType{FS: files, Root: "."}); err != nil {
		t.Fatal(err)
	}
	var planned, listed []string
	for _, plan := range store.executionSnapshot() {
		planned = append(planned, plan.finger.Id)
	}
	for _, metadata := range store.Metadata() {
		listed = append(listed, metadata.ID)
	}
	if fmt.Sprint(planned) != "[b-login d-admin a-root c-root]" || fmt.Sprint(listed) != "[a-root b-login c-root d-admin]" {
		t.Fatalf("派发顺序=%v 元数据顺序=%v", planned, listed)
	}
}
