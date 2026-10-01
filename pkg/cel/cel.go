package cel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/phuslu/lru"
)

const ruleResultsVariable = "__gxx_rule_results"

var (
	baseEnv     *cel.Env
	baseEnvOnce sync.Once
	// 小容量环境缓存使用单分片，避免默认按 CPU 分片后每片仅容纳一两个环境。
	environmentCache    = lru.NewLRUCache[string, *cel.Env](128, lru.WithShards[string, *cel.Env](1))
	programCache        = lru.NewLRUCache[programKey, cel.Program](8192, lru.WithShards[programKey, cel.Program](16))
	runtimeEnvironments = lru.NewLRUCache[programKey, *cel.Env](256, lru.WithShards[programKey, *cel.Env](1))
	environmentMu       sync.Mutex
	programMu           sync.Mutex
)

type programKey struct {
	env        *cel.Env
	expression string
	compact    bool
	evidence   bool
}

func getBaseEnv() *cel.Env {
	baseEnvOnce.Do(func() {
		opts := append(ReadCompileOptions(), cel.Variable(ruleResultsVariable, cel.MapType(cel.StringType, cel.BoolType)), cel.EnableMacroCallTracking())
		var err error
		baseEnv, err = cel.NewEnv(opts...)
		if err != nil {
			panic(fmt.Sprintf("初始化 CEL 环境失败: %v", err))
		}
	})
	return baseEnv
}

// CustomLib 只保存本次求值的数据。环境和程序是有界缓存中的不可变对象。
// 零参数规则函数在解析时展开为输入变量访问，程序不捕获其他扫描的可变状态。
type CustomLib struct {
	env             *cel.Env
	prepared        *PreparedLibrary
	declarations    map[string]*cel.Type
	ruleResults     map[string]bool
	ctx             context.Context
	requests        evaluationContext
	activation      evaluationActivation
	evidenceEnabled bool
	trace           evaluationTrace
	lastTrace       *evidencePlan
}

func NewCustomLib() *CustomLib { return &CustomLib{} }

func (c *CustomLib) SetContext(ctx context.Context) { c.ctx = ctx }

func (c *CustomLib) getEnv() (*cel.Env, error) {
	if c.env != nil {
		return c.env, nil
	}
	if len(c.declarations) == 0 && len(c.ruleResults) == 0 {
		c.env = getBaseEnv()
		return c.env, nil
	}
	keys := make([]string, 0, len(c.declarations)+len(c.ruleResults))
	for k, v := range c.declarations {
		keys = append(keys, "v:"+k+":"+v.String())
	}
	for k := range c.ruleResults {
		keys = append(keys, "r:"+k)
	}
	sort.Strings(keys)
	signature := strings.Join(keys, "\x00")
	if env, ok := environmentCache.Get(signature); ok {
		c.env = env
		return env, nil
	}
	environmentMu.Lock()
	defer environmentMu.Unlock()
	if env, ok := environmentCache.Get(signature); ok {
		c.env = env
		return env, nil
	}
	opts := make([]cel.EnvOption, 0, len(keys))
	for k, v := range c.declarations {
		opts = append(opts, cel.Variable(k, v))
	}
	for name := range c.ruleResults {
		opts = append(opts, cel.Macros(cel.GlobalMacro(name, 0, func(eh cel.MacroExprFactory, _ ast.Expr, _ []ast.Expr) (ast.Expr, *cel.Error) {
			return eh.NewCall(operators.Index, eh.NewIdent(ruleResultsVariable), eh.NewLiteral(types.String(name))), nil
		})))
	}
	env, err := getBaseEnv().Extend(opts...)
	if err != nil {
		return nil, fmt.Errorf("派生 CEL 环境失败: %w", err)
	}
	environmentCache.Set(signature, env)
	c.env = env
	return env, nil
}

func compileProgram(env *cel.Env, expression string, compact bool, evidence ...bool) (cel.Program, error) {
	traceEnabled := len(evidence) > 0 && evidence[0]
	key := programKey{env: env, expression: expression, compact: compact, evidence: traceEnabled}
	if p, ok := programCache.Get(key); ok {
		return p, nil
	}
	programMu.Lock()
	defer programMu.Unlock()
	if p, ok := programCache.Get(key); ok {
		return p, nil
	}
	tree, issues := env.Compile(expression)
	if issues.Err() != nil {
		return nil, issues.Err()
	}
	// 自定义函数可能读取时间、随机数或执行 I/O，不能进行常量求值。
	runtimeEnv := env
	if compact {
		var err error
		runtimeEnv, err = compactRuntimeEnv(env, tree)
		if err != nil {
			return nil, err
		}
	}
	programOptions := []cel.ProgramOption{cel.InterruptCheckFrequency(100)}
	var tracePlan *evidencePlan
	if traceEnabled {
		tracePlan = newEvidencePlan(tree)
	}
	programOptions = append(programOptions, cel.CustomDecoratorV2(tracePlan.decorate))
	nodes, hasLoop, waits := 0, false, false
	ast.PreOrderVisit(tree.NativeRep().Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		nodes++
		hasLoop = hasLoop || e.Kind() == ast.ComprehensionKind
		if e.Kind() == ast.CallKind {
			switch e.AsCall().FunctionName() {
			case "__gxx_sleep", "__gxx_wait", "__gxx_jndi":
				waits = true
			}
		}
	}))
	if nodes > 10000 {
		return nil, fmt.Errorf("CEL 表达式节点数超过上限")
	}
	// 简单表达式的执行步数由 AST 大小决定；只有循环需要每次求值创建成本追踪器。
	if hasLoop {
		programOptions = append(programOptions, cel.CostLimit(10000000))
	}
	p, err := runtimeEnv.Program(tree, programOptions...)
	if err == nil {
		if tracePlan != nil {
			// 节点 ID 仅供解释器构建期间装饰使用，求值阶段使用连续索引。
			tracePlan.indices = nil
		}
		p = &compiledProgram{Program: p, hasLoop: hasLoop, waits: waits, evidence: tracePlan}
		programCache.Set(key, p)
	}
	return p, err
}

// 无推导循环的程序没有解释器中断检查点。直接求值避免为每条表达式
// 注册子 context；I/O、sleep 等函数仍通过 evaluationContext 使用原始 context。
// 包含推导循环的程序保留 ContextEval 的周期中断和成本限制。
type compiledProgram struct {
	cel.Program
	hasLoop  bool
	waits    bool
	evidence *evidencePlan
}

func (p *compiledProgram) ContextEval(ctx context.Context, input any) (ref.Val, *cel.EvalDetails, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if p.hasLoop {
		return p.Program.ContextEval(ctx, input)
	}
	out, details, err := p.Eval(input)
	if ctx.Err() != nil {
		return nil, details, ctx.Err()
	}
	return out, details, err
}

// Prepare 预编译表达式，不执行表达式及其副作用。
func (c *CustomLib) Prepare(expression string) error {
	env, err := c.getEnv()
	if err != nil {
		return err
	}
	_, err = compileProgram(env, expression, true, c.evidenceEnabled)
	return err
}

func (c *CustomLib) Evaluate(expression string, variables map[string]any) (ref.Val, error) {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return c.EvaluateContext(ctx, expression, variables)
}

func (c *CustomLib) EvaluateContext(ctx context.Context, expression string, variables map[string]any) (ref.Val, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	env, err := c.getEnv()
	if err != nil {
		return nil, err
	}
	c.requests.ctx = ctx
	c.lastTrace = nil
	c.trace = evaluationTrace{}
	c.requests.trace = nil
	if c.evidenceEnabled {
		c.requests.trace = &c.trace
	}
	c.activation = evaluationActivation{variables: variables, rules: c.ruleResults, state: &c.requests}
	defer func() { c.activation = evaluationActivation{} }()
	if c.prepared != nil && env == c.prepared.env {
		for _, p := range c.prepared.programs {
			if p.expression == expression {
				if compiled, ok := p.program.(*compiledProgram); ok {
					c.lastTrace = compiled.evidence
				}
				out, _, err := p.program.ContextEval(ctx, &c.activation)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return out, err
			}
		}
	}
	p, err := compileProgram(env, expression, true, c.evidenceEnabled)
	if err != nil {
		return nil, err
	}
	if compiled, ok := p.(*compiledProgram); ok {
		c.lastTrace = compiled.evidence
	}
	out, _, err := p.ContextEval(ctx, &c.activation)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, err
}

func evalContext(ctx context.Context, env *cel.Env, expression string, params any, compact bool) (ref.Val, error) {
	p, err := compileProgram(env, expression, compact)
	if err != nil {
		return nil, err
	}
	out, _, err := p.ContextEval(ctx, params)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, err
}
func (c *CustomLib) WriteRuleFunctionsROptions(name string, value bool) {
	if c.ruleResults == nil {
		c.ruleResults = make(map[string]bool, 4)
	}
	if _, ok := c.ruleResults[name]; !ok {
		c.env = nil
	}
	c.ruleResults[name] = value
}
func (c *CustomLib) PreRegisterRuleFunctions(names []string) {
	for _, name := range names {
		if name != "" {
			c.WriteRuleFunctionsROptions(name, false)
		}
	}
}
func (c *CustomLib) BatchUpdateCompileOptions(declarations map[string]*cel.Type) {
	for k, v := range declarations {
		c.UpdateCompileOption(k, v)
	}
}
func (c *CustomLib) UpdateCompileOption(name string, t *cel.Type) {
	if c.declarations == nil {
		c.declarations = make(map[string]*cel.Type)
	}
	if old, ok := c.declarations[name]; ok && old.String() == t.String() {
		return
	}
	c.declarations[name] = t
	c.env = nil
}

// Reset 释放扫描、响应和程序引用；仅保留小型空规则表供下一次求值复用。
// CustomLib 的可变状态只属于一个执行者，不得在求值期间重置或并发使用。
func (c *CustomLib) Reset() {
	rules := c.ruleResults
	if len(rules) > 64 {
		rules = nil
	} else {
		clear(rules)
	}
	*c = CustomLib{ruleResults: rules}
}

// compactRuntimeEnv 只给已完成类型检查的 AST 装配实际调用的函数。
// 完整语言能力仍由编译环境提供，避免每条程序持有整个标准库的分发表。
// 调用方持有 programMu，派生环境与程序均为不可变对象。
func compactRuntimeEnv(env *cel.Env, tree *cel.Ast) (*cel.Env, error) {
	used := make(map[string]struct{})
	ast.PreOrderVisit(tree.NativeRep().Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		if e.Kind() == ast.CallKind {
			used[e.AsCall().FunctionName()] = struct{}{}
		}
	}))
	names := make([]string, 0, len(used))
	for name := range used {
		names = append(names, name)
	}
	sort.Strings(names)
	key := programKey{env: env, expression: strings.Join(names, "\x00"), compact: true}
	if cached, ok := runtimeEnvironments.Get(key); ok {
		return cached, nil
	}
	all := env.Functions()
	functions := make([]*decls.FunctionDecl, 0, len(names))
	for _, name := range names {
		if fn := all[name]; fn != nil {
			functions = append(functions, fn)
		}
	}
	runtimeEnv, err := cel.NewCustomEnv(cel.Container(env.Container.Name()), cel.CustomTypeAdapter(env.CELTypeAdapter()), cel.CustomTypeProvider(env.CELTypeProvider()), cel.VariableDecls(env.Variables()...), cel.FunctionDecls(functions...))
	if err == nil {
		runtimeEnvironments.Set(key, runtimeEnv)
	}
	return runtimeEnv, err
}

// evaluationActivation 为程序提供内部变量，不修改调用方传入的只读 map。
type evaluationActivation struct {
	variables map[string]any
	rules     map[string]bool
	state     *evaluationContext
}

func (a *evaluationActivation) ResolveName(name string) (any, bool) {
	switch name {
	case contextVariable:
		return a.state, true
	case ruleResultsVariable:
		return a.rules, true
	}
	value, ok := a.variables[name]
	return value, ok
}
func (*evaluationActivation) Parent() interpreter.Activation { return nil }
