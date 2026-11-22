package finger

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v2"

	celPkg "github.com/cyberspacesec/gxx/pkg/cel"
)

// RulePolicy 限制可以加载的规则。零值表示不限制；任一字段非零时策略生效，未允许的
// 能力一律拒绝：AllowTypes 为空时允许 http、tcp、udp 全部类型，否则只允许列出的类型；
// AllowRaw、AllowReverse、AllowSleep 分别允许 Raw HTTP 请求、反连检测（newReverse、
// newJNDI、wait、jndi）与 sleep；MaxRules、MaxSubRules 限制规则数与单条规则的子规则数，
// 0 表示不限制。
type RulePolicy struct {
	AllowTypes   []string
	AllowRaw     bool
	AllowReverse bool
	AllowSleep   bool
	MaxRules     int
	MaxSubRules  int
}

// Active 报告策略是否生效。
func (p RulePolicy) Active() bool {
	return len(p.AllowTypes) > 0 || p.AllowRaw || p.AllowReverse || p.AllowSleep || p.MaxRules > 0 || p.MaxSubRules > 0
}

// ErrRulePolicy 是规则违反规则策略的错误类别。
var ErrRulePolicy = errors.New("规则违反规则策略")

// PolicyError 是一处违反规则策略的内容。Field 是规则内的字段路径（如 rules.r0.request.raw）。
type PolicyError struct {
	RuleID  string
	Field   string
	Code    string
	Message string
}

func (e *PolicyError) Error() string {
	if e.RuleID == "" {
		return fmt.Sprintf("%v：%s", ErrRulePolicy, e.Message)
	}
	return fmt.Sprintf("%v：规则 %s 的 %s %s", ErrRulePolicy, e.RuleID, e.Field, e.Message)
}

func (e *PolicyError) Unwrap() error { return ErrRulePolicy }

// 规则策略的检查代码。
const (
	CodePolicyType     = "policy-type"
	CodePolicyRaw      = "policy-raw"
	CodePolicyReverse  = "policy-reverse"
	CodePolicySleep    = "policy-sleep"
	CodePolicySubRules = "policy-sub-rules"
	CodePolicyRules    = "policy-rules"
)

// CheckPolicy 返回规则违反策略的全部内容；策略未生效时返回 nil。表达式按语法解析，
// 无法解析的表达式不在这里报告（加载后求值失败，按未命中处理）。
func CheckPolicy(fg *Finger, policy RulePolicy) []*PolicyError {
	if fg == nil || !policy.Active() {
		return nil
	}
	var found []*PolicyError
	add := func(field, code, message string) {
		found = append(found, &PolicyError{RuleID: fg.Id, Field: field, Code: code, Message: message})
	}
	allowed := make([]string, 0, len(policy.AllowTypes))
	for _, kind := range policy.AllowTypes {
		allowed = append(allowed, strings.ToLower(strings.TrimSpace(kind)))
	}
	if policy.MaxSubRules > 0 && len(fg.Rules) > policy.MaxSubRules {
		add("rules", CodePolicySubRules, fmt.Sprintf("有 %d 条子规则，超过上限 %d", len(fg.Rules), policy.MaxSubRules))
	}
	checkExpression := func(field, expression string) {
		names, err := celPkg.CalledFunctions(expression)
		if err != nil {
			return
		}
		if !policy.AllowSleep && slices.Contains(names, "__gxx_sleep") {
			add(field, CodePolicySleep, "调用了 sleep")
		}
		if !policy.AllowReverse && (slices.Contains(names, "__gxx_wait") || slices.Contains(names, "__gxx_jndi")) {
			add(field, CodePolicyReverse, "使用了反连检测（wait / jndi）")
		}
	}
	checkSet := func(prefix string, values []yamlPair) {
		for _, pair := range values {
			field := prefix + "." + pair.key
			switch strings.TrimSpace(pair.value) {
			case "newReverse()", "newJNDI()":
				if !policy.AllowReverse {
					add(field, CodePolicyReverse, "创建了反连地址（"+strings.TrimSpace(pair.value)+"）")
				}
			default:
				checkExpression(field, pair.value)
			}
		}
	}
	checkSet("set", yamlPairs(fg.Set))
	checkSet("payloads.payloads", yamlPairs(fg.Payloads.Payloads))
	for _, rule := range fg.Rules {
		prefix := "rules." + rule.Key
		kind := rule.Value.Request.Type
		if kind == "" {
			kind = HttpType
		}
		if len(allowed) > 0 && !slices.Contains(allowed, kind) {
			add(prefix+".request.type", CodePolicyType, "使用了未允许的请求类型 "+kind)
		}
		if !policy.AllowRaw && strings.TrimSpace(rule.Value.Request.Raw) != "" {
			add(prefix+".request.raw", CodePolicyRaw, "使用了 Raw HTTP 请求")
		}
		checkExpression(prefix+".expression", rule.Value.Expression)
		for _, pair := range yamlPairs(rule.Value.Output) {
			checkExpression(prefix+".output."+pair.key, pair.value)
		}
	}
	checkExpression("expression", fg.Expression)
	return found
}

// CheckLibraryPolicy 检查规则库整体：规则数上限与每条规则。返回第一处违反。
func CheckLibraryPolicy(fingers []*Finger, policy RulePolicy) error {
	if !policy.Active() {
		return nil
	}
	if policy.MaxRules > 0 && len(fingers) > policy.MaxRules {
		return &PolicyError{Code: CodePolicyRules, Message: fmt.Sprintf("规则库有 %d 条规则，超过上限 %d", len(fingers), policy.MaxRules)}
	}
	for _, fg := range fingers {
		if found := CheckPolicy(fg, policy); len(found) > 0 {
			return found[0]
		}
	}
	return nil
}

type yamlPair struct{ key, value string }

func yamlPairs(items yaml.MapSlice) []yamlPair {
	pairs := make([]yamlPair, 0, len(items))
	for _, item := range items {
		pairs = append(pairs, yamlPair{yamlScalar(item.Key), yamlScalar(item.Value)})
	}
	return pairs
}
