package finger

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	yamlv3 "go.yaml.in/yaml/v3"
)

// Diagnostic 是规则校验发现的一处问题。Severity 为 error 或 warning；Line、Column 从 1
// 开始，无法定位时为 0。Field 是规则内的字段路径，如 rules.r0.request.raw。
type Diagnostic struct {
	Code     string
	Field    string
	Message  string
	Severity string
	Line     int
	Column   int
}

// 诊断的严重程度。
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// 诊断代码。
const (
	CodeYAML              = "yaml"               // YAML 语法或结构错误，规则无法加载
	CodeUnknownKey        = "unknown-key"        // 未知的键
	CodeMissingID         = "missing-id"         // 缺少 id
	CodeMissingName       = "missing-name"       // 缺少 info.name
	CodeMissingRules      = "missing-rules"      // 没有子规则
	CodeMissingExpression = "missing-expression" // 缺少总表达式
	CodeExpression        = "expression-compile" // 表达式无法编译
	CodeInvalidProduct    = "invalid-product"    // info.product 缺少必填项或取值不合规
	CodeMissingServices   = "missing-services"   // TCP/UDP 规则没有声明 info.services
	CodeInvalidService    = "invalid-service"    // info.services 的一项不合规
)

// ValidateOptions 是规则校验的选项。
type ValidateOptions struct {
	// Strict 为 true 时，规范性问题（未知键、缺少必填信息、产品与服务声明不合规、表达式无法编译）报告为 error；
	// 否则报告为 warning，与引擎宽松加载的行为一致。
	Strict bool
	// Policy 与加载时使用的规则策略相同；违反策略总是 error。
	Policy RulePolicy
}

var yamlLinePattern = regexp.MustCompile(`line (\d+)`)

// Validate 校验一条规则的内容，不发请求。非严格模式下 error 与引擎拒绝加载一一对应：
// YAML 无法解析（含不支持的请求类型）或违反规则策略；其余问题为 warning。严格模式
// 把规范性问题也报告为 error，用于入库前检查。库级限制（MaxRules）不适用于单条规则。
func Validate(content []byte, opts ValidateOptions) []Diagnostic {
	var out []Diagnostic
	var root yamlv3.Node
	located := yamlv3.Unmarshal(content, &root) == nil
	locate := func(field string) (int, int) {
		if !located {
			return 0, 0
		}
		return nodePosition(&root, field)
	}
	fg, err := Parse(content, "")
	if err != nil {
		line := 0
		if match := yamlLinePattern.FindStringSubmatch(err.Error()); match != nil {
			line, _ = strconv.Atoi(match[1])
		}
		diagnostic := Diagnostic{Code: CodeYAML, Message: err.Error(), Severity: SeverityError, Line: line}
		if line == 0 {
			// 类型校验等在解码阶段报出的错误带有子规则名称，按名称定位。
			if key := failingRule(err.Error()); key != "" {
				diagnostic.Field = "rules." + key + ".request.type"
				diagnostic.Line, diagnostic.Column = locate(diagnostic.Field)
			}
		}
		return append(out, diagnostic)
	}
	for _, violation := range CheckPolicy(fg, opts.Policy) {
		line, column := locate(violation.Field)
		out = append(out, Diagnostic{Code: violation.Code, Field: violation.Field, Message: violation.Message, Severity: SeverityError, Line: line, Column: column})
	}
	conformance := SeverityWarning
	if opts.Strict {
		conformance = SeverityError
	}
	add := func(code, field, message string) {
		line, column := locate(field)
		out = append(out, Diagnostic{Code: code, Field: field, Message: message, Severity: conformance, Line: line, Column: column})
	}
	if located && len(root.Content) == 1 {
		checkKeys(root.Content[0], "", fingerSchema, add)
	}
	if strings.TrimSpace(fg.Id) == "" {
		add(CodeMissingID, "id", "缺少规则标识 id")
	}
	validateInfo(fg, add)
	if len(fg.Rules) == 0 {
		add(CodeMissingRules, "rules", "没有子规则")
	}
	for _, failed := range CheckExpressions(fg) {
		field := "expression"
		if failed.Rule != "" {
			field = "rules." + failed.Rule + ".expression"
		} else if strings.TrimSpace(fg.Expression) == "" {
			add(CodeMissingExpression, field, "缺少总表达式")
			continue
		}
		add(CodeExpression, field, "表达式无法编译："+failed.Err.Error())
	}
	return out
}

// validateInfo 校验 info 中的规则信息。规则信息的必填项与取值约束集中在这里。
func validateInfo(fg *Finger, add func(code, field, message string)) {
	if strings.TrimSpace(fg.Info.Name) == "" {
		add(CodeMissingName, "info.name", "缺少规则名称 info.name")
	}
	if fg.Info.Product != nil {
		validateProduct(*fg.Info.Product, add)
	}
	validateServices(fg, add)
}

// 产品声明的格式与上限。
var (
	productIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*$`)
	productTagPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

const (
	maxProductIDLength          = 96
	maxProductNameLength        = 200
	maxProductTags              = 8
	maxProductAliases           = 16
	maxProductReferences        = 16
	maxProductDescriptionLength = 500
)

// validateProduct 校验 info.product 的必填项、枚举取值与列表上限。
func validateProduct(product Product, add func(code, field, message string)) {
	report := func(field, message string) { add(CodeInvalidProduct, "info.product."+field, message) }
	switch {
	case product.ID == "":
		report("id", "缺少产品标识 info.product.id")
	case len(product.ID) > maxProductIDLength || !productIDPattern.MatchString(product.ID):
		report("id", fmt.Sprintf("产品标识 %q 须为“厂商段.产品段”，各段由小写字母、数字与连字符组成，总长不超过 %d", product.ID, maxProductIDLength))
	}
	switch {
	case strings.TrimSpace(product.Name) == "":
		report("name", "缺少产品名称 info.product.name")
	case utf8.RuneCountInString(product.Name) > maxProductNameLength:
		report("name", fmt.Sprintf("产品名称超过 %d 个字符", maxProductNameLength))
	}
	enum := func(field, label, value string, allowed []string) {
		switch {
		case value == "":
			report(field, "缺少"+label+" info.product."+field)
		case !slices.Contains(allowed, value):
			report(field, fmt.Sprintf("未知的%s %q，可选 %s", label, value, strings.Join(allowed, "、")))
		}
	}
	enum("category", "产品分类", product.Category, ProductCategories)
	enum("identity", "产品身份", product.Identity, ProductIdentities)
	enum("assurance", "可信度", product.Assurance, ProductAssurances)
	list := func(field, label string, values []string, limit int, valid func(string) bool, invalid string) {
		if len(values) > limit {
			report(field, fmt.Sprintf("%s有 %d 个，超过上限 %d", label, len(values), limit))
		}
		for index, value := range values {
			item := fmt.Sprintf("%s.%d", field, index)
			if !valid(value) {
				report(item, fmt.Sprintf("%s %q %s", label, value, invalid))
			} else if slices.Index(values, value) != index {
				report(item, fmt.Sprintf("重复的%s %q", label, value))
			}
		}
	}
	list("tags", "标签", product.Tags, maxProductTags, productTagPattern.MatchString, "须由小写字母、数字与连字符组成")
	list("aliases", "别名", product.Aliases, maxProductAliases, func(value string) bool { return strings.TrimSpace(value) != "" }, "不能为空")
	list("cpe", "CPE", product.CPE, len(product.CPE), ValidCPE, "不是有效的 CPE 2.3 格式化字符串")
	list("references", "参考链接", product.References, maxProductReferences, ValidReferenceURL, "须为不含账号信息的 http(s) 链接，且不是占位域名")
	if product.Assurance == "verified" && len(product.References) == 0 {
		report("references", "可信度为 verified 时至少需要一个官方参考链接")
	}
	if utf8.RuneCountInString(product.Description) > maxProductDescriptionLength {
		report("description", fmt.Sprintf("产品描述超过 %d 个字符", maxProductDescriptionLength))
	}
}

// validateServices 校验 info.services；TCP/UDP 规则必须声明识别的服务。
func validateServices(fg *Finger, add func(code, field, message string)) {
	network := false
	for _, rule := range fg.Rules {
		network = network || rule.Value.Request.Type == TcpType || rule.Value.Request.Type == UdpType
	}
	if network && len(fg.Info.Services) == 0 {
		add(CodeMissingServices, "info.services", "TCP/UDP 规则需要在 info.services 中声明识别的服务")
	}
	for index, service := range fg.Info.Services {
		prefix := fmt.Sprintf("info.services.%d", index)
		if strings.TrimSpace(service.Protocol) == "" {
			add(CodeInvalidService, prefix+".protocol", "缺少服务协议 protocol")
		}
		if service.Transport != TcpType && service.Transport != UdpType {
			add(CodeInvalidService, prefix+".transport", fmt.Sprintf("传输层协议 %q 须为 tcp 或 udp", service.Transport))
		}
		if len(service.Ports) == 0 {
			add(CodeInvalidService, prefix+".ports", "缺少端口 ports")
		}
		for position, port := range service.Ports {
			if port < 1 || port > 65535 {
				add(CodeInvalidService, fmt.Sprintf("%s.ports.%d", prefix, position), fmt.Sprintf("端口 %d 须在 1–65535 之间", port))
			}
		}
	}
}

var failingRulePattern = regexp.MustCompile(`规则 (\S+): 不支持的请求类型`)

func failingRule(message string) string {
	if match := failingRulePattern.FindStringSubmatch(message); match != nil {
		return match[1]
	}
	return ""
}

// keySchema 描述一层允许的键：keys 给出映射的键与对应的下一层；each 非空时映射的每个
// 键都套用它（子规则名称由用户命名）；items 非空时该层是列表，每一项套用它；freeform
// 表示不再检查（用户自定义的键，如 set、output、headers、info.metadata）。
type keySchema struct {
	keys     map[string]*keySchema
	each     *keySchema
	items    *keySchema
	freeform bool
}

// yamlKeys 由结构体的 yaml 标签生成允许的键，结构体增加字段时校验同步认识它。
func yamlKeys(value any) map[string]*keySchema {
	keys := make(map[string]*keySchema)
	t := reflect.TypeOf(value)
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if tag != "" && tag != "-" {
			keys[tag] = &keySchema{freeform: true}
		}
	}
	return keys
}

var fingerSchema = func() *keySchema {
	request := &keySchema{keys: yamlKeys(RuleRequest{})}
	rule := &keySchema{keys: yamlKeys(Rule{})}
	rule.keys["request"] = request
	info := &keySchema{keys: yamlKeys(Info{})}
	info.keys["classification"] = &keySchema{keys: yamlKeys(Classification{})}
	info.keys["product"] = &keySchema{keys: yamlKeys(Product{})}
	info.keys["services"] = &keySchema{items: &keySchema{keys: yamlKeys(Service{})}}
	// 附加元数据由调用方自定义，引擎只透传，内部的键不检查。
	info.keys["metadata"] = &keySchema{freeform: true}
	payloads := &keySchema{keys: yamlKeys(Payloads{})}
	root := &keySchema{keys: yamlKeys(Finger{})}
	root.keys["rules"] = &keySchema{each: rule}
	root.keys["info"] = info
	root.keys["payloads"] = payloads
	return root
}()

// checkKeys 报告映射中不在 schema 内的键；列表项的字段路径以序号表示，如 info.services.0.ports。
func checkKeys(node *yamlv3.Node, prefix string, schema *keySchema, add func(code, field, message string)) {
	if node == nil || schema == nil || schema.freeform {
		return
	}
	if schema.items != nil {
		if node.Kind == yamlv3.SequenceNode {
			for index, item := range node.Content {
				checkKeys(item, prefix+"."+strconv.Itoa(index), schema.items, add)
			}
		}
		return
	}
	if node.Kind != yamlv3.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		field := key
		if prefix != "" {
			field = prefix + "." + key
		}
		if schema.each != nil {
			checkKeys(value, field, schema.each, add)
			continue
		}
		child, known := schema.keys[key]
		if !known {
			add(CodeUnknownKey, field, "未知的键 "+key)
			continue
		}
		checkKeys(value, field, child, add)
	}
}

// nodePosition 返回字段路径（以 . 分隔，列表项用序号）对应的行列：映射给出键的位置，
// 列表给出该项的位置；找不到时返回最近的上级。
func nodePosition(root *yamlv3.Node, field string) (int, int) {
	node := root
	if node.Kind == yamlv3.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	line, column := 0, 0
	segments := strings.Split(field, ".")
	for index := 0; index < len(segments); index++ {
		if node.Kind == yamlv3.SequenceNode {
			position, err := strconv.Atoi(segments[index])
			if err != nil || position < 0 || position >= len(node.Content) {
				break
			}
			node = node.Content[position]
			line, column = node.Line, node.Column
			continue
		}
		if node.Kind != yamlv3.MappingNode {
			break
		}
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			// 子规则名称本身可能含点，按剩余路径的最长匹配查找。
			for end := len(segments); end > index; end-- {
				if node.Content[i].Value == strings.Join(segments[index:end], ".") {
					line, column = node.Content[i].Line, node.Content[i].Column
					node, found = node.Content[i+1], true
					index = end - 1
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			break
		}
	}
	return line, column
}
