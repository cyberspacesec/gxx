package cel

import "github.com/google/cel-go/cel"

type preparedExpression struct {
	expression string
	program    cel.Program
}

// PreparedLibrary 属于只读规则快照。加载时固定环境和程序，运行时只创建
// 本次扫描的规则结果与请求状态，避免为每个目标重复拼接环境签名和查询缓存。
type PreparedLibrary struct {
	env       *cel.Env
	rules     []string
	programs  []preparedExpression
	batchSafe bool
}

func PrepareLibrary(rules, expressions []string, evidence ...bool) (*PreparedLibrary, error) {
	lib := NewCustomLib()
	lib.PreRegisterRuleFunctions(rules)
	env, err := lib.getEnv()
	if err != nil {
		return nil, err
	}
	p := &PreparedLibrary{env: env, rules: append([]string(nil), rules...), programs: make([]preparedExpression, 0, len(expressions)), batchSafe: true}
	for _, expression := range expressions {
		program, err := compileProgram(env, expression, true, evidence...)
		if err != nil {
			return nil, err
		}
		p.programs = append(p.programs, preparedExpression{expression, program})
		if compiled, ok := program.(*compiledProgram); !ok || compiled.hasLoop || compiled.waits {
			p.batchSafe = false
		}
	}
	return p, nil
}

// BatchSafe 表明内置执行计划不包含推导循环、等待或反连 I/O。
// 请求是否已缓存仍由 Runner 判断，动态规则沿用逐条调度路径。
func (p *PreparedLibrary) BatchSafe() bool { return p != nil && p.batchSafe }

func (p *PreparedLibrary) NewEvaluation() *CustomLib {
	lib := NewCustomLib()
	p.InitEvaluation(lib)
	return lib
}

// InitEvaluation 为独占的执行状态绑定只读程序，旧的规则结果、动态声明和
// 请求配置均不跨指纹复用。p 为 nil 时使用动态编译路径。
func (p *PreparedLibrary) InitEvaluation(lib *CustomLib) {
	lib.Reset()
	if p != nil {
		lib.PreRegisterRuleFunctions(p.rules)
		lib.env = p.env
		lib.prepared = p
	}
}
