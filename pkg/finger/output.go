package finger

import (
	"fmt"
	"strings"
	"unicode/utf8"

	gcel "github.com/cyberspacesec/gxx/v2/pkg/cel"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"gopkg.in/yaml.v2"
)

// EvaluateOutput 仅保存成功求值的输出。失败的提取表达式不作为产品版本或证据回传。
// 执行变量保留完整值，公开结果中的单项输出限制为 512 字节。
func EvaluateOutput(args yaml.MapSlice, variables map[string]any, lib *gcel.CustomLib) map[string]string {
	var outputs map[string]string
	for _, argument := range args {
		key, keyOK := argument.Key.(string)
		expression, expressionOK := argument.Value.(string)
		if !keyOK || !expressionOK {
			continue
		}
		delete(variables, key)
		out, err := lib.Evaluate(expression, variables)
		if err != nil || out == nil {
			continue
		}
		var value string
		switch current := out.(type) {
		case types.String:
			value = string(current)
			variables[key] = value
			lib.UpdateCompileOption(key, cel.StringType)
		case types.Int:
			value = fmt.Sprint(int64(current))
			variables[key] = int(current)
			lib.UpdateCompileOption(key, cel.IntType)
		default:
			variables[key] = out.Value()
			lib.UpdateCompileOption(key, cel.DynType)
			continue
		}
		if key == "product_version" && (len(value) > 128 || strings.ContainsAny(value, "\r\n\x00")) {
			continue
		}
		if outputs == nil {
			outputs = make(map[string]string)
		}
		if len(outputs) >= 64 && key != "product_version" {
			continue
		}
		if len(value) > 512 {
			end := 512
			for !utf8.RuneStart(value[end]) {
				end--
			}
			value = value[:end]
		}
		outputs[key] = strings.Clone(value)
	}
	return outputs
}
