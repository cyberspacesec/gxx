package finger

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"

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
)

// ValidateOptions 是规则校验的选项。
type ValidateOptions struct {
	// Strict 为 true 时，规范性问题（未知键、缺少必填信息、表达式无法编译）报告为 error；
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
	validateInfo(fg.Info, add)
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
func validateInfo(info Info, add func(code, field, message string)) {
	if strings.TrimSpace(info.Name) == "" {
		add(CodeMissingName, "info.name", "缺少规则名称 info.name")
	}
}

var failingRulePattern = regexp.MustCompile(`规则 (\S+): 不支持的请求类型`)

func failingRule(message string) string {
	if match := failingRulePattern.FindStringSubmatch(message); match != nil {
		return match[1]
	}
	return ""
}

// keySchema 描述一层映射允许的键；children 给出键对应的下一层，nil 表示不再检查
// （用户自定义的键，如 set、output、headers）。each 为 true 表示下一层的每个键都套用 children。
type keySchema struct {
	keys     map[string]*keySchema
	each     *keySchema
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
	payloads := &keySchema{keys: yamlKeys(Payloads{})}
	root := &keySchema{keys: yamlKeys(Finger{})}
	root.keys["rules"] = &keySchema{each: rule}
	root.keys["info"] = info
	root.keys["payloads"] = payloads
	return root
}()

// checkKeys 报告映射中不在 schema 内的键。
func checkKeys(node *yamlv3.Node, prefix string, schema *keySchema, add func(code, field, message string)) {
	if node == nil || node.Kind != yamlv3.MappingNode || schema == nil || schema.freeform {
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

// nodePosition 返回字段路径（以 . 分隔）对应值所在的行列；找不到时返回最近的上级。
func nodePosition(root *yamlv3.Node, field string) (int, int) {
	node := root
	if node.Kind == yamlv3.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	line, column := 0, 0
	segments := strings.Split(field, ".")
	for index := 0; index < len(segments); index++ {
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
