package sdk

import (
	"github.com/cyberspacesec/gxx/pkg/finger"
)

// RulePolicy 限制引擎可以加载的规则。零值表示不限制；任一字段非零时策略生效，
// 未允许的能力一律拒绝：
//   - AllowTypes 为空时允许 http、tcp、udp 全部类型，否则只允许列出的类型；
//   - AllowRaw 允许 Raw HTTP 请求；
//   - AllowReverse 允许反连检测（set 中的 newReverse()/newJNDI()，表达式中的 wait、jndi）；
//   - AllowSleep 允许表达式调用 sleep；
//   - MaxRules、MaxSubRules 限制规则数与单条规则的子规则数，0 表示不限制。
//
// 只允许 HTTP、其余全部禁止可以写成 RulePolicy{AllowTypes: []string{"http"}}；
// 允许全部类型但禁止 raw、反连与 sleep 可以写成 RulePolicy{AllowTypes: []string{"http", "tcp", "udp"}}。
type RulePolicy = finger.RulePolicy

// RulePolicyError 是一处违反规则策略的内容，含规则标识与字段路径（如 rules.r0.request.raw）。
// NewEngine 与 LoadFingerOptions 返回的错误可用 errors.As 取得它。
type RulePolicyError = finger.PolicyError

// WithRulePolicy 设置规则策略：加载（含 LoadFingerOptions 重新加载）时逐条检查，
// 违反即返回错误（errors.Is(err, ErrRulePolicy)），错误中含规则标识与字段。
// 内置规则库同样受检查。
func WithRulePolicy(policy RulePolicy) Option {
	snapshot := policy
	snapshot.AllowTypes = append([]string(nil), policy.AllowTypes...)
	return func(c *engineConfig) error {
		c.rulePolicy = snapshot
		c.rulePolicy.AllowTypes = append([]string(nil), snapshot.AllowTypes...)
		return nil
	}
}

// Diagnostic 是规则校验发现的一处问题。Severity 为 "error" 或 "warning"；Line、Column 从 1
// 开始，无法定位时为 0；Field 是字段路径，列表项用序号表示（如 info.services.0.ports）。
// Code 取值：yaml（无法解析，含不支持的请求类型）、unknown-key、missing-id、missing-name、
// missing-rules、missing-expression、expression-compile、invalid-product（产品声明缺少
// 必填项或取值不合规）、missing-services（TCP/UDP 规则没有声明服务）、invalid-service，
// 以及规则策略的 policy-type、policy-raw、policy-reverse、policy-sleep、policy-sub-rules。
type Diagnostic struct {
	Code     string `json:"code"`
	Field    string `json:"field,omitempty"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

// ValidateOptions 是 ValidateRule 的选项。Strict 为 true 时规范性问题（未知键、缺少
// 必填信息、产品与服务声明不合规、表达式无法编译）报告为 error，否则为 warning；
// Policy 与 WithRulePolicy 相同。
type ValidateOptions struct {
	Strict bool
	Policy RulePolicy
}

// ValidateRule 校验一条规则的内容，不发请求，没有问题时返回空切片。
//
// 非严格模式下，存在 error 当且仅当使用同样 Policy 的 NewEngine 拒绝加载这条规则：
// YAML 无法解析（含不支持的请求类型）或违反规则策略；其他问题报告为 warning，
// 不影响加载。严格模式另把规范性问题报告为 error，用于规则入库前的检查。
// 库级限制 MaxRules 不适用于单条规则。
func ValidateRule(content []byte, opts ValidateOptions) []Diagnostic {
	found := finger.Validate(content, finger.ValidateOptions{Strict: opts.Strict, Policy: opts.Policy})
	out := make([]Diagnostic, len(found))
	for i, item := range found {
		out[i] = Diagnostic(item)
	}
	return out
}
