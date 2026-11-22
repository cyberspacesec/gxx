package finger

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Product 是规则声明的产品信息（info.product）。规则自带的声明是产品信息的来源；
// 同一个产品标识在全部规则中的声明必须完全相同，规则库加载时检查。
type Product struct {
	ID          string   `yaml:"id"`          // 厂商段.产品段，如 weaver.e-cology
	Name        string   `yaml:"name"`        // 规范产品名
	Vendor      string   `yaml:"vendor"`      // 厂商规范名，不确定时留空
	Category    string   `yaml:"category"`    // 产品分类，取值见 ProductCategories
	Identity    string   `yaml:"identity"`    // product：命中即确认产品；signal：技术线索
	Assurance   string   `yaml:"assurance"`   // verified：厂商与产品已确认；inferred：由规则名称与特征推断
	Tags        []string `yaml:"tags"`        // 产品级用途标签
	Aliases     []string `yaml:"aliases"`     // 别名与旧名
	CPE         []string `yaml:"cpe"`         // CPE 2.3，只在有依据时填写
	References  []string `yaml:"references"`  // 官方主页、文档或仓库
	Description string   `yaml:"description"` // 产品简介
}

// Service 是 TCP/UDP 规则识别的服务（info.services 的一项）。
type Service struct {
	Protocol  string `yaml:"protocol"`  // 应用层协议，如 ssh、mysql
	Transport string `yaml:"transport"` // tcp 或 udp
	Ports     []int  `yaml:"ports"`     // 常见端口，1–65535
}

// 产品声明的取值范围。
var (
	ProductCategories = []string{"application", "middleware", "framework", "operating-system", "cms", "database",
		"web-server", "security", "library", "hosting-panel", "device", "network-device", "iot", "other"}
	ProductIdentities = []string{"product", "signal"}
	ProductAssurances = []string{"verified", "inferred"}
)

// Equal 报告两份产品声明是否完全相同；未填写的列表与空列表视为相同。
func (p Product) Equal(other Product) bool {
	return p.differingField(other) == ""
}

// differingField 返回第一个不同的字段名，相同时返回空串。
func (p Product) differingField(other Product) string {
	switch {
	case p.ID != other.ID:
		return "id"
	case p.Name != other.Name:
		return "name"
	case p.Vendor != other.Vendor:
		return "vendor"
	case p.Category != other.Category:
		return "category"
	case p.Identity != other.Identity:
		return "identity"
	case p.Assurance != other.Assurance:
		return "assurance"
	case !slices.Equal(p.Tags, other.Tags):
		return "tags"
	case !slices.Equal(p.Aliases, other.Aliases):
		return "aliases"
	case !slices.Equal(p.CPE, other.CPE):
		return "cpe"
	case !slices.Equal(p.References, other.References):
		return "references"
	case p.Description != other.Description:
		return "description"
	}
	return ""
}

// Clone 返回不与原值共享切片的副本。
func (p Product) Clone() Product {
	p.Tags, p.Aliases = slices.Clone(p.Tags), slices.Clone(p.Aliases)
	p.CPE, p.References = slices.Clone(p.CPE), slices.Clone(p.References)
	return p
}

// CloneServices 返回不与原值共享端口列表的副本。
func CloneServices(services []Service) []Service {
	if services == nil {
		return nil
	}
	result := slices.Clone(services)
	for index := range result {
		result[index].Ports = slices.Clone(result[index].Ports)
	}
	return result
}

// CloneMetadata 深拷贝 info.metadata。解析后的取值只含映射、列表与标量，见 normalizeMetadata。
func CloneMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return nil
	}
	return cloneMetadataValue(metadata).(map[string]any)
}

func cloneMetadataValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneMetadataValue(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneMetadataValue(item)
		}
		return result
	}
	return value
}

// normalizeMetadata 把 YAML 解出的嵌套映射统一为 map[string]any，使附加元数据可以直接
// 编码为 JSON；非字符串的键按其文本形式保存。
func normalizeMetadata(value any) any {
	switch typed := value.(type) {
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = normalizeMetadata(item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = normalizeMetadata(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = normalizeMetadata(item)
		}
		return result
	}
	return value
}

// ProductConflictError 表示同一产品标识在两条规则中的声明不一致。
type ProductConflictError struct {
	ProductID string
	RuleIDs   [2]string
	Field     string
}

func (e *ProductConflictError) Error() string {
	return fmt.Sprintf("产品 %s 的声明不一致：规则 %s 与 %s 的 %s 不同", e.ProductID, e.RuleIDs[0], e.RuleIDs[1], e.Field)
}

// CheckProductDeclarations 检查同一产品标识在全部规则中的声明完全相同，返回第一处不一致。
// 未声明产品或产品标识为空的规则不参与比较。
func CheckProductDeclarations(fingers []*Finger) error {
	first := make(map[string]*Finger)
	for _, fg := range fingers {
		if fg == nil || fg.Info.Product == nil || fg.Info.Product.ID == "" {
			continue
		}
		product := fg.Info.Product
		seen, exists := first[product.ID]
		if !exists {
			first[product.ID] = fg
			continue
		}
		if field := seen.Info.Product.differingField(*product); field != "" {
			return &ProductConflictError{ProductID: product.ID, RuleIDs: [2]string{seen.Id, fg.Id}, Field: field}
		}
	}
	return nil
}

// ValidReferenceURL 报告链接能否作为参考资料：http(s)、有主机名、不含账号信息，
// 且不是 example.com 一类的占位域名。
func ValidReferenceURL(reference string) bool {
	parsed, err := url.Parse(strings.TrimSpace(reference))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && host != "" && host != "example.com" &&
		!strings.HasSuffix(host, ".example.com") && parsed.User == nil
}

// ValidCPE 报告取值是否为结构完整的 CPE 2.3 格式化字符串。属性可包含转义冒号，
// 只按未转义的分隔符拆分 11 个属性。
func ValidCPE(value string) bool {
	if !strings.HasPrefix(value, "cpe:2.3:") {
		return false
	}
	attributes := make([]string, 0, 11)
	start, escaped := len("cpe:2.3:"), false
	for index := start; index < len(value); index++ {
		if value[index] < ' ' || value[index] >= 127 {
			return false
		}
		if escaped {
			escaped = false
			continue
		}
		if value[index] == '\\' {
			escaped = true
		} else if value[index] == ':' {
			attributes = append(attributes, value[start:index])
			start = index + 1
		} else if value[index] == ' ' {
			return false
		}
	}
	attributes = append(attributes, value[start:])
	if escaped || len(attributes) != 11 || !slices.Contains([]string{"a", "h", "o", "*", "-"}, attributes[0]) {
		return false
	}
	return !slices.Contains(attributes, "")
}
