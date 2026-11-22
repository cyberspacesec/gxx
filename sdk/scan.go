package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/cyberspacesec/gxx/internal/lifecycle"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/pkg/runner"
)

// NetworkPolicy 约束引擎的全部出站连接：HTTP、Raw HTTP、TCP、UDP、图标、附属资源、
// 跳转、TLS 探测与代理健康探测。各字段为 nil 时保持默认行为，字段说明见 network.Policy。
type NetworkPolicy = network.Policy

// TargetRequest 描述一次即将发往目标的连接，供 NetworkPolicy.CheckTarget 判断。
type TargetRequest = network.TargetRequest

// RequestKind 是一次出站连接的用途。
type RequestKind = network.RequestKind

// RedirectAction 是 NetworkPolicy.Redirect 对一次跳转的决定。
type RedirectAction = network.RedirectAction

// 出站连接的用途。
const (
	RequestHTTP     = network.RequestHTTP
	RequestRaw      = network.RequestRaw
	RequestTCP      = network.RequestTCP
	RequestUDP      = network.RequestUDP
	RequestIcon     = network.RequestIcon
	RequestResource = network.RequestResource
	RequestTLS      = network.RequestTLS
)

// 跳转决定。
const (
	RedirectFollow = network.RedirectFollow
	RedirectStop   = network.RedirectStop
)

// WithNetworkPolicy 设置引擎级网络策略，作用于该引擎的全部扫描与基础信息请求。
//
// Dial 替代直连拨号，配置代理时用于连接代理服务器本身；CheckTarget 在每次发往目标之前
// 调用（含重试、跳转与经代理隧道的目标），返回错误即拒绝且不会有任何字节发往该目标；
// Redirect 可以阻止跟随 30x、刷新与脚本跳转，不访问的地址记入 RedirectTo；
// WrapTransport 包装 HTTP 请求的底层 RoundTripper。
func WithNetworkPolicy(policy NetworkPolicy) Option {
	return func(c *engineConfig) error {
		c.policy = policy
		return nil
	}
}

// scanConfig 是单次扫描的附加配置。
type scanConfig struct {
	policy   NetworkPolicy
	report   *EvaluationReport
	observer func(Exchange)
	limits   ExchangeLimits
}

// ScanOption 配置一次 ScanWith 或 DebugRule。
type ScanOption func(*scanConfig)

// ScanNetworkPolicy 设置本次扫描的网络策略，逐字段覆盖引擎级策略：非 nil 的字段替换
// 引擎级的同名字段，nil 字段沿用引擎级。
//
// 设置了 Dial 时，本次扫描的 HTTP 连接不进入连接池，不同扫描的拨号互不混用；
// 已缓存的 Transport 照常复用，不为每次扫描新建 Transport。
func ScanNetworkPolicy(policy NetworkPolicy) ScanOption {
	return func(c *scanConfig) { c.policy = policy }
}

// ScanWith 与 Scan 相同，并应用本次扫描的附加配置。未传任何选项时与 Scan 完全一致。
func (e *Engine) ScanWith(ctx context.Context, target string, opts ...ScanOption) (*TargetResult, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, ErrEmptyTarget
	}
	var cfg scanConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	res, err := e.runner.ScanTargetWith(ctx, target, cfg.runnerOptions())
	if err != nil {
		return nil, fmt.Errorf("scan target %q: %w", target, errors.Join(ErrScanFailed, err))
	}
	if res == nil {
		return nil, fmt.Errorf("%w: target=%s", ErrEmptyResult, target)
	}
	out := e.convertTargetResult(res)
	e.dispatchWriter(ctx, out)
	return out, nil
}

func (c *scanConfig) runnerOptions() runner.ScanOptions {
	return runner.ScanOptions{Policy: c.policy, Report: c.report, Observer: c.observer, ExchangeLimits: c.limits}
}

// FailureStage 是规则求值不完整的原因：request（请求失败）、expression（表达式运行错误）、
// non_bool（结果不是布尔值）、extract（输出提取失败）、regex_timeout（正则匹配超时，
// 按未命中处理）、panic（求值 panic）、budget（正文截断、计算成本或记录超出上限）。
type FailureStage = runner.FailureStage

// 求值失败的原因。
const (
	StageRequest      = runner.StageRequest
	StageExpression   = runner.StageExpression
	StageNonBool      = runner.StageNonBool
	StageExtract      = runner.StageExtract
	StageRegexTimeout = runner.StageRegexTimeout
	StagePanic        = runner.StagePanic
	StageBudget       = runner.StageBudget
)

// EvaluationFailure 是一处使结论不完整的原因。Message 是有界文本（最多 256 字节），不含响应正文。
type EvaluationFailure = runner.EvaluationFailure

// RuleEvaluation 是一条规则的求值情况：Completed 为 true 表示每个子规则都取得了响应并
// 正常求值，Matched 与普通扫描的命中结果一致。SourceSHA256 是规则文件内容的摘要。
type RuleEvaluation = runner.RuleEvaluation

// EvaluationReport 报告一次扫描中每条规则是否完整求值。它不改变普通匹配语义，只说明
// 结论是否完整：Complete 为 true 表示全部规则都已执行且没有任何失败；Truncated 表示
// 记录超出上限（每条规则 16 条失败、每次扫描 65536 条规则）而被省略，此时 Complete 为 false。
type EvaluationReport = runner.EvaluationReport

// ScanEvaluationReport 在扫描结束后（含失败与取消）把求值报告写入 dst，覆盖其原有内容。
func ScanEvaluationReport(dst *EvaluationReport) ScanOption {
	return func(c *scanConfig) { c.report = dst }
}

// Exchange 是一次请求与响应的记录，字段说明见 network.Exchange。
type Exchange = network.Exchange

// ExchangeLimits 限制交换记录的大小与数量；零值字段取默认值（正文 64 KiB、
// 请求头与响应头各 64 KiB、每次扫描 10000 条），MaxBody、MaxHeader 为负数时不复制。
type ExchangeLimits = network.ExchangeLimits

// ScanObserver 在本次扫描的每次交换完成后回调 observe：入口与跳转、规则请求（HTTP、
// Raw、TCP、UDP）、图标、附属资源与 TLS 探测；规则复用本次扫描已有响应时回调一条
// Cached 记录。回调在发出请求的协程中串行执行，Sequence 按回调顺序递增；记录中的
// 切片与映射只读，需要保留时自行复制。并发的多次扫描各自回调，互不串扰。
func ScanObserver(observe func(Exchange), limits ExchangeLimits) ScanOption {
	return func(c *scanConfig) { c.observer, c.limits = observe, limits }
}

// SubRuleDebug 是单条子规则的中间结果。Result 为 nil 表示没有得到布尔结论（请求失败、
// 表达式出错或扫描取消）；Exchanges 是该子规则使用的交换记录，复用已有响应时为 Cached 记录。
type SubRuleDebug struct {
	Key        string             `json:"key"`
	Expression string             `json:"expression"`
	Result     *bool              `json:"result"`
	Exchanges  []Exchange         `json:"-"`
	Evidence   []MatchEvidence    `json:"evidence,omitempty"`
	Outputs    map[string]string  `json:"outputs,omitempty"`
	Failure    *EvaluationFailure `json:"failure,omitempty"`
}

// RuleDebug 是单条规则的调试结果。Match 为 nil 表示未命中。入口跳转链上有多页时，
// SubRules 描述决定结果的那次评估：命中的那一页，未命中时为最后一页。
type RuleDebug struct {
	Match      *FingerMatch   `json:"match,omitempty"`
	SubRules   []SubRuleDebug `json:"sub_rules"`
	Evaluation RuleEvaluation `json:"evaluation"`
}

// DebugRule 按扫描的方式对 target 只执行规则 ruleID，返回每条子规则的表达式结果、
// 交换记录、证据、输出与失败原因。入口跳转链、请求缓存、网络策略与求值规则都与
// Scan 相同，结论与扫描一致；调试总是采集证据，结果不交给 Writer。
// opts 中的 ScanNetworkPolicy、ScanEvaluationReport 与 ScanObserver 同样生效。
func (e *Engine) DebugRule(ctx context.Context, target, ruleID string, opts ...ScanOption) (*RuleDebug, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if target == "" {
		return nil, ErrEmptyTarget
	}
	var cfg scanConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	debug, err := e.runner.DebugRule(ctx, target, ruleID, cfg.runnerOptions())
	if err != nil {
		return nil, fmt.Errorf("debug rule %q on %q: %w", ruleID, target, errors.Join(ErrScanFailed, err))
	}
	out := &RuleDebug{Evaluation: debug.Evaluation, SubRules: make([]SubRuleDebug, 0, len(debug.SubRules))}
	for _, sub := range debug.SubRules {
		item := SubRuleDebug{Key: sub.Key, Expression: sub.Expression, Result: sub.Result, Exchanges: sub.Exchanges, Outputs: sub.Outputs, Failure: sub.Failure}
		for _, evidence := range sub.Evidence {
			item.Evidence = append(item.Evidence, MatchEvidence(evidence))
		}
		out.SubRules = append(out.SubRules, item)
	}
	if debug.Match != nil {
		converted := e.convertTargetResult(&runner.TargetResult{Matches: []*runner.FingerMatch{debug.Match}})
		if len(converted.Matches) == 1 {
			out.Match = &converted.Matches[0]
		}
	}
	return out, nil
}
