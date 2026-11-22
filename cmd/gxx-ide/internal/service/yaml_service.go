package service

import (
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v2"

	fingerpkg "github.com/cyberspacesec/gxx/pkg/finger"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
)

// YamlService 处理 YAML 校验、解析等业务。
type YamlService struct{}

// NewYamlService 返回 YamlService。
func NewYamlService() *YamlService { return &YamlService{} }

var yamlLineColPattern = regexp.MustCompile(`(?i)line (\d+)(?::\s*column (\d+))?`)

// Validate 解析用户提交的 YAML 文本，返回是否合法及概要。
func (s *YamlService) Validate(content string) *model.ValidateYAMLOutput {
	out := &model.ValidateYAMLOutput{}
	if strings.TrimSpace(content) == "" {
		out.Errors = []model.YAMLValidationError{{Message: "YAML 内容为空"}}
		return out
	}
	var f fingerpkg.Finger
	if err := yaml.Unmarshal([]byte(content), &f); err != nil {
		out.Errors = []model.YAMLValidationError{parseYAMLError(err.Error())}
		return out
	}
	out.Outline = BuildOutline(&f)
	// YAML 结构正确后再编译每条表达式：语法残缺、未定义的函数与变量在这里报出，
	// 不必等到运行指纹。
	for _, failed := range fingerpkg.CheckExpressions(&f) {
		where := "总表达式"
		if failed.Rule != "" {
			where = "规则 " + failed.Rule + " 的表达式"
		}
		out.Errors = append(out.Errors, model.YAMLValidationError{
			Line:    expressionLine(content, failed.Rule),
			Message: where + "：" + celErrorSummary(failed.Err),
		})
	}
	out.Warnings = standardFormatWarnings(content)
	out.Valid = len(out.Errors) == 0
	return out
}

// standardFormatWarnings 用引擎的严格校验检查指纹标准格式：规则标识、产品声明（info.product）、
// TCP/UDP 规则的服务声明（info.services）、未知键与必填信息。YAML 结构与表达式编译已在上面
// 报为错误，这里不重复。
func standardFormatWarnings(content string) []model.YAMLValidationError {
	var warnings []model.YAMLValidationError
	for _, diagnostic := range fingerpkg.Validate([]byte(content), fingerpkg.ValidateOptions{Strict: true}) {
		switch diagnostic.Code {
		case fingerpkg.CodeYAML, fingerpkg.CodeExpression, fingerpkg.CodeMissingExpression:
			continue
		}
		warnings = append(warnings, model.YAMLValidationError{Line: diagnostic.Line, Column: diagnostic.Column, Field: diagnostic.Field, Message: diagnostic.Message})
	}
	return warnings
}

// expressionLine 返回规则（rule 为空时是指纹本身）的 expression 所在行，找不到时为 0。
func expressionLine(content, rule string) int {
	lines := strings.Split(content, "\n")
	if rule == "" {
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.HasPrefix(lines[i], "expression:") {
				return i + 1
			}
		}
		return 0
	}
	inRule := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if indent := len(line) - len(strings.TrimLeft(line, " ")); indent > 0 && indent <= 4 && (trimmed == rule+":" || strings.HasPrefix(trimmed, rule+": ")) {
			inRule = true
			continue
		}
		if inRule && strings.HasPrefix(trimmed, "expression:") {
			return i + 1
		}
	}
	return 0
}

// celErrorSummary 取 CEL 编译错误的第一条说明，去掉源码定位与指示符行。
func celErrorSummary(err error) string {
	message := err.Error()
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		message = message[:i]
	}
	if i := strings.Index(message, "ERROR: <input>:"); i >= 0 {
		rest := message[i+len("ERROR: <input>:"):]
		if j := strings.Index(rest, ": "); j >= 0 {
			return strings.TrimSpace(rest[j+2:])
		}
	}
	return strings.TrimSpace(message)
}

// parseYAMLError 从 yaml.v2 错误中尽力提取行号 / 列号。
func parseYAMLError(raw string) model.YAMLValidationError {
	err := model.YAMLValidationError{Message: raw}
	if m := yamlLineColPattern.FindStringSubmatch(raw); m != nil {
		if line, e := strconv.Atoi(m[1]); e == nil {
			err.Line = line
		}
		if len(m) >= 3 && m[2] != "" {
			if col, e := strconv.Atoi(m[2]); e == nil {
				err.Column = col
			}
		}
	}
	return err
}

// BuildOutline 把 finger.Finger 转为前端友好的 outline。
//
// 注意：本函数被 yaml_service / library_service / finger_service 共同使用，
// 因此声明为包级公开符号。
func BuildOutline(f *fingerpkg.Finger) *model.FingerOutline {
	out := &model.FingerOutline{
		ID:          f.Id,
		Name:        f.Info.Name,
		Author:      f.Info.Author,
		Severity:    f.Info.Severity,
		Tags:        f.Info.Tags,
		Description: f.Info.Description,
		Expression:  f.Expression,
	}
	for _, rule := range f.Rules {
		out.RuleKeys = append(out.RuleKeys, rule.Key)
		out.Rules = append(out.Rules, model.RuleOutline{
			Key:        rule.Key,
			Type:       firstNonEmpty(rule.Value.Request.Type, "http"),
			Method:     rule.Value.Request.Method,
			Path:       rule.Value.Request.Path,
			Expression: rule.Value.Expression,
		})
	}
	for _, kv := range f.Set {
		if key, ok := kv.Key.(string); ok {
			out.SetVars = append(out.SetVars, key)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
