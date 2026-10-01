package service

import (
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	fingerpkg "github.com/cyberspacesec/gxx/v2/pkg/finger"

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
	out.Valid = true
	out.Outline = BuildOutline(&f)
	return out
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
