package runner

import (
	"context"
	"fmt"
	"sync"

	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/network"
)

// SubRuleDebug 是单条子规则在一次评估中的中间结果。Result 为 nil 表示没有得到
// 布尔结论（请求失败、表达式出错或扫描取消）。Exchanges 是该子规则使用的交换记录，
// 复用本次扫描已有响应时为 Cached 记录。
type SubRuleDebug struct {
	Key        string
	Expression string
	Result     *bool
	Exchanges  []network.Exchange
	Evidence   []cel.Evidence
	Outputs    map[string]string
	Failure    *EvaluationFailure
}

// RuleDebug 是单条规则按扫描方式执行一次的完整中间结果。Match 为 nil 表示未命中。
// 入口跳转链上有多页时，SubRules 描述决定结果的那次评估：命中的那一页，未命中时为最后一页。
type RuleDebug struct {
	Match      *FingerMatch
	SubRules   []SubRuleDebug
	Evaluation RuleEvaluation
	// Result 是只执行这条规则的扫描结果（入口跳转链、标题、证书等与普通扫描相同）。
	Result *TargetResult
}

// ruleDebug 是一次评估（一页）的子规则记录。
type ruleDebug struct {
	subRules []SubRuleDebug
	from, to int // 本次评估期间产生的交换记录区间
}

func (d *ruleDebug) noteFailure(subRule string, failure EvaluationFailure) {
	for i := range d.subRules {
		if d.subRules[i].Key == subRule && d.subRules[i].Failure == nil {
			copied := failure
			d.subRules[i].Failure = &copied
			return
		}
	}
}

// debugCollector 收集单规则调试的交换记录与选定的评估。
type debugCollector struct {
	ruleID    string
	mu        sync.Mutex
	exchanges []network.Exchange
	chosen    *ruleDebug
}

func (c *debugCollector) observe(ex network.Exchange) {
	c.mu.Lock()
	c.exchanges = append(c.exchanges, ex)
	c.mu.Unlock()
}

func (c *debugCollector) mark() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.exchanges)
}

// result 把本规则的交换记录分配给所选评估的各子规则。
func (c *debugCollector) result() []SubRuleDebug {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.chosen == nil {
		return nil
	}
	subRules := c.chosen.subRules
	for _, ex := range c.exchanges[c.chosen.from:min(c.chosen.to, len(c.exchanges))] {
		if ex.RuleID != c.ruleID {
			continue
		}
		for i := range subRules {
			if subRules[i].Key == ex.SubRule {
				subRules[i].Exchanges = append(subRules[i].Exchanges, ex)
			}
		}
	}
	return subRules
}

// DebugRule 按扫描的方式对 target 只执行规则 ruleID，返回每条子规则的表达式结果、
// 交换记录、证据、输出与失败原因。结论与普通扫描一致：入口跳转链、请求缓存、
// 网络策略与求值规则完全相同，只是强制采集证据。
func (r *Runner) DebugRule(ctx context.Context, target, ruleID string, opts ScanOptions) (*RuleDebug, error) {
	var plan *fingerExecutionPlan
	for _, entry := range r.store.executionSnapshot() {
		if entry.finger != nil && entry.finger.Id == ruleID {
			// 动态编译路径与预编译程序语义相同，并能为调试采集证据。
			plan = &fingerExecutionPlan{finger: entry.finger}
			break
		}
	}
	if plan == nil {
		return nil, fmt.Errorf("规则 %q 不存在", ruleID)
	}
	collector := &debugCollector{ruleID: ruleID}
	user := opts.Observer
	opts.Observer = func(ex network.Exchange) {
		collector.observe(ex)
		if user != nil {
			user(ex)
		}
	}
	var report EvaluationReport
	requested := opts.Report
	opts.Report = &report
	result, err := r.scanTarget(ctx, target, opts, []fingerExecutionPlan{*plan}, collector)
	if requested != nil {
		*requested = report
	}
	if err != nil {
		return nil, err
	}
	out := &RuleDebug{SubRules: collector.result(), Result: result}
	if len(report.Rules) > 0 {
		out.Evaluation = report.Rules[0]
	} else {
		out.Evaluation = RuleEvaluation{RuleID: ruleID, SourceSHA256: plan.finger.Source.SHA256}
	}
	for _, match := range result.Matches {
		if match.Finger != nil && match.Finger.Id == ruleID {
			out.Match = match
		}
	}
	return out, nil
}

// debugSubRule 返回本次评估中子规则 key 的记录，必要时新建。
func (d *ruleDebug) subRule(key, expression string) *SubRuleDebug {
	for i := range d.subRules {
		if d.subRules[i].Key == key {
			return &d.subRules[i]
		}
	}
	d.subRules = append(d.subRules, SubRuleDebug{Key: key, Expression: expression})
	return &d.subRules[len(d.subRules)-1]
}
