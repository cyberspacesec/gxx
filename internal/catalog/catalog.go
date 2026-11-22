// Package catalog 由规则文件中的产品声明生成 SDK 的内置产品目录（sdk/catalog.json）。
//
// 产品目录不再手工维护：每条内置规则在 info.product 中声明产品，同一产品标识的声明在
// 全部规则中完全相同；目录按产品标识归并声明并列出声明它的规则标识。生成结果是确定的
// （产品按标识排序，规则标识排序），SDK 的测试断言入库的 catalog.json 与规则文件一致。
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sort"

	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/utils/common"
)

// Product 是目录中的一个产品，字段与 sdk.ProductDefinition 的 JSON 形式相同。
type Product struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor,omitempty"`
	Category    string   `json:"category,omitempty"`
	Identity    string   `json:"identity,omitempty"`
	Assurance   string   `json:"assurance,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	CPE         []string `json:"cpe,omitempty"`
	References  []string `json:"references,omitempty"`
	Description string   `json:"description,omitempty"`
	RuleIDs     []string `json:"rule_ids"`
}

// Build 读取 fsys 中的全部规则，返回按产品标识排序的产品目录。内置规则库要求每条规则都
// 声明产品、规则标识不重复、同一产品标识的声明完全相同，任一不满足即返回错误。
func Build(fsys fs.FS) ([]Product, error) {
	var fingers []*finger.Finger
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !common.IsYamlFile(path) {
			return err
		}
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		fg, err := finger.Parse(content, path)
		if err != nil {
			return fmt.Errorf("解析 %s: %w", path, err)
		}
		fingers = append(fingers, fg)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(fingers) == 0 {
		return nil, fmt.Errorf("没有找到规则文件")
	}
	if err := finger.CheckProductDeclarations(fingers); err != nil {
		return nil, err
	}
	products := make(map[string]*Product)
	rules := make(map[string]string)
	for _, fg := range fingers {
		if previous, exists := rules[fg.Id]; exists {
			return nil, fmt.Errorf("规则标识 %s 重复：%s 与 %s", fg.Id, previous, fg.Source.Path)
		}
		rules[fg.Id] = fg.Source.Path
		declared := fg.Info.Product
		if declared == nil || declared.ID == "" {
			return nil, fmt.Errorf("%s 没有声明产品 info.product", fg.Source.Path)
		}
		product, exists := products[declared.ID]
		if !exists {
			value := declared.Clone()
			product = &Product{ID: value.ID, Name: value.Name, Vendor: value.Vendor, Category: value.Category,
				Identity: value.Identity, Assurance: value.Assurance, Tags: value.Tags, Aliases: value.Aliases,
				CPE: value.CPE, References: value.References, Description: value.Description}
			products[declared.ID] = product
		}
		product.RuleIDs = append(product.RuleIDs, fg.Id)
	}
	result := make([]Product, 0, len(products))
	for _, product := range products {
		slices.Sort(product.RuleIDs)
		result = append(result, *product)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// Generate 返回 fsys 中规则对应的 catalog.json 内容：两个空格缩进，不转义 HTML 字符，以换行结尾。
func Generate(fsys fs.FS) ([]byte, error) {
	products, err := Build(fsys)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(struct {
		Products []Product `json:"products"`
	}{products}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
