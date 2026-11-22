package utils

import (
	"encoding/csv"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	finger2 "github.com/cyberspacesec/gxx/pkg/finger"
)

var builtinRuleID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// builtinRules 加载内置规则库，按规则标识索引。
func builtinRules(t *testing.T) map[string]*finger2.Finger {
	t.Helper()
	rules, err := GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]*finger2.Finger, len(rules))
	for _, rule := range rules {
		if _, exists := byID[rule.Id]; exists {
			t.Fatalf("规则标识重复: %s", rule.Id)
		}
		byID[rule.Id] = rule
	}
	return byID
}

// 内置库：全部规则可加载，标识唯一且合规，文件位于 <分类>/<标识>.yaml 且分类与产品声明一致，
// 每条规则声明产品，同一产品的声明一致，verified 产品都有参考链接。
func TestBuiltinLibraryLayoutAndDeclarations(t *testing.T) {
	rules := builtinRules(t)
	if len(rules) != 2348 {
		t.Fatalf("内置规则数量变化: %d", len(rules))
	}
	// 磁盘上的每个规则文件都在嵌入库中：嵌入模式只收 <分类>/*.yaml，放错位置或用 .yml
	// 扩展名的文件会被静默遗漏。
	files := 0
	err := fs.WalkDir(os.DirFS("."), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		if d.IsDir() {
			if strings.Contains(name, "/") || !slices.Contains(finger2.ProductCategories, name) {
				t.Errorf("规则目录 %s 不是产品分类", name)
			}
			return nil
		}
		if strings.HasSuffix(name, ".go") && !strings.Contains(name, "/") {
			return nil
		}
		files++
		if !strings.HasSuffix(name, ".yaml") {
			t.Errorf("规则文件 %s 的扩展名应为 .yaml", name)
		}
		if _, err := embeddedFingerFS.ReadFile(name); err != nil {
			t.Errorf("规则文件 %s 没有进入嵌入库: %v", name, err)
		}
		return nil
	})
	if err != nil || files != len(rules) {
		t.Fatalf("磁盘规则文件 %d 个，嵌入规则 %d 条，err=%v", files, len(rules), err)
	}
	all := make([]*finger2.Finger, 0, len(rules))
	for id, rule := range rules {
		all = append(all, rule)
		if len(id) < 3 || len(id) > 96 || !builtinRuleID.MatchString(id) {
			t.Errorf("规则标识不合规: %q", id)
		}
		product := rule.Info.Product
		if product == nil || product.ID == "" {
			t.Errorf("%s 没有声明产品", id)
			continue
		}
		if want := product.Category + "/" + id + ".yaml"; rule.Source.Path != want {
			t.Errorf("%s 位于 %s，应为 %s", id, rule.Source.Path, want)
		}
		if product.Assurance == "verified" && len(product.References) == 0 {
			t.Errorf("%s 的产品 %s 为 verified 却没有参考链接", id, product.ID)
		}
		for _, failure := range finger2.Validate(mustRead(t, rule.Source.Path), finger2.ValidateOptions{Strict: true}) {
			t.Errorf("%s 不符合标准格式: %+v", id, failure)
		}
	}
	if err := finger2.CheckProductDeclarations(all); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := embeddedFingerFS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readCSV(t *testing.T, name string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return records
}

// 标识对照表覆盖全部 2,349 条旧规则：每条现有规则恰好由一条 renamed 记录对应，被合并的规则
// 指向保留规则，旧标识与旧路径不重复；核对表与对照表逐行对应，产品信息与规则声明一致。
func TestBuiltinLibraryIDMapCoversAllOldRules(t *testing.T) {
	rules := builtinRules(t)
	idMap := readCSV(t, "指纹标识对照表.csv")
	if !slices.Equal(idMap[0], []string{"old_id", "old_path", "new_id", "new_path", "product_id", "action"}) {
		t.Fatalf("对照表表头不符: %v", idMap[0])
	}
	rows := idMap[1:]
	if len(rows) != 2349 {
		t.Fatalf("对照表应覆盖 v1.7.0 的 2,349 条规则，实际 %d 行", len(rows))
	}
	oldIDs, oldPaths, renamed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	sourceDirs := []string{"fingerYaml/jiajiu/", "fingerYaml/fofa/", "fingerYaml/fingers/", "fingerYaml/fingerprints/"}
	for _, row := range rows {
		oldID, oldPath, newID, newPath, productID, action := row[0], row[1], row[2], row[3], row[4], row[5]
		if oldID == "" || oldIDs[oldID] || oldPaths[oldPath] {
			t.Fatalf("旧标识或旧路径为空或重复: %v", row)
		}
		oldIDs[oldID], oldPaths[oldPath] = true, true
		if !slices.ContainsFunc(sourceDirs, func(dir string) bool { return strings.HasPrefix(oldPath, dir) }) {
			t.Fatalf("旧路径不在原来源目录中: %v", row)
		}
		rule, exists := rules[newID]
		if !exists {
			t.Fatalf("对照表指向不存在的规则: %v", row)
		}
		if newPath != path.Join("fingerYaml", rule.Source.Path) || productID != rule.Info.Product.ID {
			t.Fatalf("对照表的新路径或产品与规则不一致: %v", row)
		}
		switch action {
		case "renamed":
			if renamed[newID] {
				t.Fatalf("新标识 %s 对应多条 renamed 记录", newID)
			}
			renamed[newID] = true
		case "merged":
		default:
			t.Fatalf("未知的 action: %v", row)
		}
	}
	if len(renamed) != len(rules) {
		t.Fatalf("有 %d 条规则没有对应的旧规则", len(rules)-len(renamed))
	}

	review := readCSV(t, "指纹核对表.csv")
	if !slices.Equal(review[0], []string{"old_id", "new_id", "product_id", "product_name", "vendor", "category", "identity", "assurance", "confidence", "doubt"}) {
		t.Fatalf("核对表表头不符: %v", review[0])
	}
	if len(review) != len(idMap) {
		t.Fatalf("核对表 %d 行，对照表 %d 行", len(review), len(idMap))
	}
	for index, row := range review[1:] {
		product := rules[row[1]].Info.Product
		if row[0] != rows[index][0] || row[1] != rows[index][2] || row[2] != product.ID || row[3] != product.Name || row[4] != product.Vendor ||
			row[5] != product.Category || row[6] != product.Identity || row[7] != product.Assurance || !slices.Contains([]string{"high", "medium", "low"}, row[8]) {
			t.Fatalf("核对表第 %d 行与规则不一致: %v", index+2, row)
		}
	}
}
