package finger

import (
	"errors"
	"strings"

	"cel.dev/cel-go/cel"

	celPkg "github.com/cyberspacesec/gxx/pkg/cel"
)

// ExpressionError 是一条编译不通过的表达式。Rule 为空表示指纹的总表达式。
type ExpressionError struct {
	Rule       string
	Expression string
	Err        error
}

// CheckExpressions 编译指纹的每条规则表达式和总表达式，返回编译不通过的各项。
// 只编译、不发请求也不求值。set、payloads 与 output 定义的变量在运行时才有
// 确定的类型，这里按任意类型声明，因此只报告语法错误、未定义的函数与变量。
func CheckExpressions(fg *Finger) []ExpressionError {
	lib := celPkg.NewCustomLib()
	keys := make([]string, 0, len(fg.Rules))
	for _, rule := range fg.Rules {
		if rule.Key != "" {
			keys = append(keys, rule.Key)
		}
		for _, output := range rule.Value.Output {
			declareDynamic(lib, yamlScalar(output.Key))
		}
	}
	lib.PreRegisterRuleFunctions(keys)
	for _, arg := range fg.Set {
		declareDynamic(lib, yamlScalar(arg.Key))
	}
	for _, arg := range fg.Payloads.Payloads {
		declareDynamic(lib, yamlScalar(arg.Key))
	}

	var failed []ExpressionError
	check := func(rule, expression string) {
		if strings.TrimSpace(expression) == "" {
			failed = append(failed, ExpressionError{rule, expression, errors.New("表达式为空")})
		} else if err := lib.Prepare(expression); err != nil {
			failed = append(failed, ExpressionError{rule, expression, err})
		}
	}
	for _, rule := range fg.Rules {
		check(rule.Key, rule.Value.Expression)
	}
	if strings.TrimSpace(fg.Expression) != "" || len(fg.Rules) == 0 {
		check("", fg.Expression)
	}
	return failed
}

func declareDynamic(lib *celPkg.CustomLib, name string) {
	if name != "" {
		lib.UpdateCompileOption(name, cel.DynType)
	}
}
