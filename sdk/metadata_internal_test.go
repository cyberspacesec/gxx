package sdk

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fingerYaml "github.com/cyberspacesec/gxx/fingerYaml"
	"github.com/cyberspacesec/gxx/internal/catalog"
)

func TestProductReferencesValidation(t *testing.T) {
	if len(validReferences([]string{"https://EXAMPLE.COM", "https://test.example.com.", "", "https://user:pass@example.org/", "https://httpd.apache.org/", "https://httpd.apache.org/"})) != 1 {
		t.Fatal("无效引用或占位链接进入结果")
	}
}

// 内置产品目录由规则文件生成：入库的 catalog.json 必须与 fingerYaml/ 的产品声明逐字节一致。
func TestBuiltinCatalogMatchesRules(t *testing.T) {
	generated, err := catalog.Generate(os.DirFS(filepath.Join("..", "fingerYaml")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, catalogData) {
		t.Fatal("sdk/catalog.json 与 fingerYaml/ 的产品声明不一致，执行 go generate ./sdk 重新生成")
	}
}

// 专项样本记录只指向内置规则库中存在的规则，且绑定规则文件的实际 SHA256；规则文件变化后
// 必须重新执行样本测试更新记录。
func TestBuiltinValidationsBindActualRuleFiles(t *testing.T) {
	if err := loadCatalog(); err != nil {
		t.Fatal(err)
	}
	rules, err := fingerYaml.GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	digests := make(map[string]string, len(rules))
	for _, rule := range rules {
		digests[rule.Id] = rule.Source.SHA256
	}
	if len(builtinCatalog.Validations) == 0 {
		t.Fatal("没有专项样本记录")
	}
	for _, record := range builtinCatalog.Validations {
		digest, exists := digests[record.RuleID]
		if !exists {
			t.Fatalf("专项样本记录指向不存在的规则: %s", record.RuleID)
		}
		if !strings.EqualFold(record.RuleSHA256, digest) {
			t.Fatalf("规则 %s 的专项样本记录与规则文件不一致，执行 go test ./sdk -run TestFullCorpusProductSamples -update-validations", record.RuleID)
		}
	}
}
