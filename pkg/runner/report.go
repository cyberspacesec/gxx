package runner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
)

// FailureStage 是规则求值不完整的原因。
type FailureStage string

const (
	StageRequest      FailureStage = "request"       // 子规则的请求失败
	StageExpression   FailureStage = "expression"    // 表达式运行错误
	StageNonBool      FailureStage = "non_bool"      // 表达式结果不是布尔值
	StageExtract      FailureStage = "extract"       // 输出提取失败
	StageRegexTimeout FailureStage = "regex_timeout" // 正则匹配超时，按未命中处理
	StagePanic        FailureStage = "panic"         // 求值过程 panic
	StageBudget       FailureStage = "budget"        // 超出资源预算：正文截断、计算成本或记录上限
)

// EvaluationFailure 是一处使结论不完整的原因。Message 是有界文本，不含响应正文。
type EvaluationFailure struct {
	RuleID  string
	SubRule string
	Stage   FailureStage
	Message string
}

// RuleEvaluation 是一条规则的求值情况。Completed 为 true 表示每个子规则都取得了响应
// 并正常求值；Matched 与普通扫描的命中结果一致。
type RuleEvaluation struct {
	RuleID       string
	SourceSHA256 string
	Completed    bool
	Matched      bool
	Failures     []EvaluationFailure
}

// EvaluationReport 报告一次扫描中每条规则是否完整求值，不改变普通匹配语义。
// Complete 为 true 表示全部规则都已执行且没有任何失败；Truncated 表示记录超出上限被省略。
type EvaluationReport struct {
	Complete  bool
	Rules     []RuleEvaluation
	Truncated bool
}

// 记录上限：规则记录数、每条规则的失败数与单条消息长度。
const (
	maxReportRules     = 1 << 16
	maxRuleFailures    = 16
	maxFailureMessage  = 256
	messageEllipsisLen = len("…")
)

// evaluationCollector 收集一次扫描的规则求值记录；规则并发执行，写入需要加锁。
type evaluationCollector struct {
	mu        sync.Mutex
	rules     []RuleEvaluation
	truncated bool
	expected  int
}

// add 写入一条规则记录。trace 的失败记录超过上限时报告标记为已截断。
func (c *evaluationCollector) add(trace *ruleTrace, fg *finger.Finger, matched bool) {
	record := trace.record(fg, matched)
	c.mu.Lock()
	defer c.mu.Unlock()
	if trace.dropped {
		c.truncated = true
	}
	if len(c.rules) >= maxReportRules {
		c.truncated = true
		return
	}
	c.rules = append(c.rules, record)
}

// report 生成最终报告。canceled 表示扫描被取消或中途失败。
func (c *evaluationCollector) report(canceled bool) EvaluationReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	rules := slices.Clone(c.rules)
	slices.SortStableFunc(rules, func(a, b RuleEvaluation) int { return strings.Compare(a.RuleID, b.RuleID) })
	complete := !canceled && !c.truncated && len(rules) == c.expected
	for _, rule := range rules {
		if !rule.Completed {
			complete = false
			break
		}
	}
	return EvaluationReport{Complete: complete, Rules: rules, Truncated: c.truncated}
}

// ruleTrace 收集一条规则一次评估中的失败与调试信息，只属于执行该规则的协程。
type ruleTrace struct {
	ruleID   string
	failures []EvaluationFailure
	dropped  bool
	debug    *ruleDebug
}

func (t *ruleTrace) fail(subRule string, stage FailureStage, message string) {
	if t == nil {
		return
	}
	if len(t.failures) >= maxRuleFailures {
		t.dropped = true
		return
	}
	t.failures = append(t.failures, EvaluationFailure{RuleID: t.ruleID, SubRule: subRule, Stage: stage, Message: boundedMessage(message)})
	if t.debug != nil {
		t.debug.noteFailure(subRule, t.failures[len(t.failures)-1])
	}
}

// failure 记录一次表达式求值错误，按原因归类。
func (t *ruleTrace) failure(ctx context.Context, subRule string, lib *cel.CustomLib, err error) {
	if t == nil || ctx.Err() != nil {
		return
	}
	switch {
	case lib.RegexTimedOut():
		t.fail(subRule, StageRegexTimeout, "正则匹配超时，按未命中处理")
	case cel.IsBudgetError(err):
		t.fail(subRule, StageBudget, "表达式超出计算成本上限")
	case cel.IsPanicError(err):
		t.fail(subRule, StagePanic, err.Error())
	default:
		t.fail(subRule, StageExpression, err.Error())
	}
}

// regexTimeout 记录求值成功但有正则匹配超时的情况：超时的匹配按未命中处理，结论可能不完整。
func (t *ruleTrace) regexTimeout(subRule string, lib *cel.CustomLib) {
	if t != nil && lib.RegexTimedOut() {
		t.fail(subRule, StageRegexTimeout, "正则匹配超时，按未命中处理")
	}
}

// requestFailure 记录子规则的请求失败；扫描取消引起的失败不计入。
func (t *ruleTrace) requestFailure(ctx context.Context, subRule string, err error) {
	if t == nil || ctx.Err() != nil {
		return
	}
	var denied *network.DeniedError
	if errors.As(err, &denied) {
		t.fail(subRule, StageRequest, "网络策略拒绝了请求")
		return
	}
	t.fail(subRule, StageRequest, err.Error())
}

// record 生成规则的求值记录。
func (t *ruleTrace) record(fg *finger.Finger, matched bool) RuleEvaluation {
	failures := t.failures
	if t.dropped {
		failures = append(failures, EvaluationFailure{RuleID: fg.Id, Stage: StageBudget, Message: fmt.Sprintf("失败记录超过 %d 条，其余省略", maxRuleFailures)})
	}
	return RuleEvaluation{RuleID: fg.Id, SourceSHA256: fg.Source.SHA256, Completed: len(failures) == 0, Matched: matched, Failures: failures}
}

// boundedMessage 把失败说明限制在 maxFailureMessage 字节内，按 UTF-8 字符边界截断。
func boundedMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) <= maxFailureMessage {
		return message
	}
	end := maxFailureMessage - messageEllipsisLen
	for end > 0 && message[end]&0xC0 == 0x80 {
		end--
	}
	return message[:end] + "…"
}
