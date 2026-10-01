package cel

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	scantypes "github.com/cyberspacesec/gxx/v2/types"
	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"github.com/dlclark/regexp2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"reflect"
	"time"
)

const contextVariable = "__gxx_context"

var contextType = types.NewObjectType("gxx.context")

type evaluationContext struct {
	ctx     context.Context
	client  *network.HTTPClient
	options network.OptionsRequest
	reverse scantypes.ReverseConfig
	trace   *evaluationTrace
}

func (v *evaluationContext) ConvertToNative(t reflect.Type) (any, error) {
	if reflect.TypeOf(v).AssignableTo(t) {
		return v, nil
	}
	return nil, fmt.Errorf("不支持的上下文转换: %v", t)
}
func (v *evaluationContext) ConvertToType(t ref.Type) ref.Val {
	if t == contextType {
		return v
	}
	return types.NewErr("不支持的上下文类型")
}
func (v *evaluationContext) Equal(other ref.Val) ref.Val { return types.Bool(v == other) }
func (v *evaluationContext) Type() ref.Type              { return contextType }
func (v *evaluationContext) Value() any                  { return v }

// SetRequestOptions 让反连查询遵循所属扫描实例的代理、超时与限流策略。
func (c *CustomLib) SetRequestOptions(client *network.HTTPClient, opts network.OptionsRequest) {
	c.requests.client, c.requests.options = client, opts
}

// SetReverseConfig 绑定当前执行者的反连配置，Reset 时一并清除。
func (c *CustomLib) SetReverseConfig(config scantypes.ReverseConfig) {
	c.requests.reverse = config
}

func (c *CustomLib) ReverseConfig() scantypes.ReverseConfig {
	return c.requests.reverse
}
func (v *evaluationContext) get(target string) ([]byte, error) {
	client := v.client
	if client == nil {
		client = network.DefaultHTTPClient()
	}
	opts := v.options
	if opts.Timeout <= 0 {
		opts.Timeout = network.DefaultTimeout
	}
	resp, err := client.SendRequestHttp(v.ctx, "GET", target, "", opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return network.ReadResponseBody(resp, network.MaxDefaultBody)
}
func waitContext(ctx context.Context, seconds int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if seconds <= 0 {
		return nil
	}
	if seconds > int64((1<<63-1)/time.Second) {
		return fmt.Errorf("等待时间超出范围")
	}
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func contextEnvOptions() []cel.EnvOption {
	opts := []cel.EnvOption{cel.Variable(contextVariable, cel.DynType)}
	for _, name := range []string{"bcontains", "ibcontains"} {
		opts = append(opts, cel.Macros(cel.ReceiverMacro(name, 1, func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
			return eh.NewCall("__gxx_"+name, eh.NewIdent(contextVariable), target, args[0]), nil
		})))
		opts = append(opts, cel.Function("__gxx_"+name, cel.Overload("gxx_"+name+"_context_bytes_bytes", []*cel.Type{cel.DynType, cel.BytesType, cel.BytesType}, cel.BoolType, cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			state, ok := args[0].Value().(*evaluationContext)
			if !ok {
				return types.NewErr("缺少执行上下文")
			}
			return types.Bool(containsResponse(state.ctx, []byte(args[1].(types.Bytes)), []byte(args[2].(types.Bytes)), name == "ibcontains"))
		}))))
	}
	opts = append(opts, cel.Macros(cel.ReceiverMacro("bsubmatch", 1, func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
		return eh.NewCall("__gxx_bsubmatch", eh.NewIdent(contextVariable), target, args[0]), nil
	})))
	opts = append(opts, cel.Function("__gxx_bsubmatch", cel.Overload("gxx_bsubmatch_context_string_bytes", []*cel.Type{cel.DynType, cel.StringType, cel.BytesType}, cel.MapType(cel.StringType, cel.StringType), cel.FunctionBinding(func(args ...ref.Val) ref.Val {
		state, ok := args[0].Value().(*evaluationContext)
		if !ok {
			return types.NewErr("缺少执行上下文")
		}
		pattern, ok := args[1].(types.String)
		if !ok {
			return types.NewErr("正则表达式必须为 string")
		}
		value, ok := args[2].(types.Bytes)
		if !ok {
			return types.NewErr("正则提取输入必须为 bytes")
		}
		re, err := getCachedRegexp2(string(pattern), regexp2.RE2)
		if err != nil {
			return types.NewErr("正则表达式无效: %v", err)
		}
		// 字符缓冲与匹配函数共用扫描预算，分组字符串独立于完整响应。
		result := make(map[string]string)
		if match, _ := re.FindRunesMatch(regexResponseRunes(state.ctx, value)); match != nil {
			for index, group := range match.Groups() {
				if index != 0 {
					result[group.Name] = group.String()
				}
			}
		}
		return types.NewStringStringMap(types.DefaultTypeAdapter, result)
	}))))
	opts = append(opts, cel.Macros(cel.ReceiverMacro("bmatches", 1, func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
		return eh.NewCall("__gxx_bmatches", eh.NewIdent(contextVariable), target, args[0]), nil
	})))
	opts = append(opts, cel.Function("__gxx_bmatches", cel.Overload("gxx_bmatches_context_string_bytes", []*cel.Type{cel.DynType, cel.StringType, cel.BytesType}, cel.BoolType, cel.FunctionBinding(func(args ...ref.Val) ref.Val {
		state, ok := args[0].Value().(*evaluationContext)
		if !ok {
			return types.NewErr("缺少执行上下文")
		}
		pattern, ok := args[1].(types.String)
		if !ok {
			return types.NewErr("正则表达式必须为 string")
		}
		value, ok := args[2].(types.Bytes)
		if !ok {
			return types.NewErr("响应查找参数必须为 bytes")
		}
		re, err := getCachedRegexp2(string(pattern), 0)
		if err != nil {
			return types.NewErr("正则表达式无效: %v", err)
		}
		matched, err := re.MatchRunes(regexResponseRunes(state.ctx, value))
		if err != nil {
			return types.NewErr("%v", err)
		}
		return types.Bool(matched)
	}))))

	opts = append(opts, cel.Macros(cel.GlobalMacro("sleep", 1, func(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
		return eh.NewCall("__gxx_sleep", eh.NewIdent(contextVariable), args[0]), nil
	})))
	opts = append(opts, cel.Function("__gxx_sleep", cel.Overload("gxx_sleep_context_int", []*cel.Type{cel.DynType, cel.IntType}, cel.NullType, cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
		state, ok := lhs.Value().(*evaluationContext)
		if !ok {
			return types.NewErr("缺少执行上下文")
		}
		if err := waitContext(state.ctx, int64(rhs.(types.Int))); err != nil {
			return types.NewErr("%v", err)
		}
		return types.NullValue
	}))))
	for _, name := range []string{"wait", "jndi"} {
		opts = append(opts, cel.Macros(cel.ReceiverMacro(name, 1, func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
			return eh.NewCall("__gxx_"+name, eh.NewIdent(contextVariable), target, args[0]), nil
		})))
		opts = append(opts, cel.Function("__gxx_"+name, cel.Overload("gxx_"+name+"_context_reverse_int", []*cel.Type{cel.DynType, cel.DynType, cel.IntType}, cel.BoolType, cel.FunctionBinding(func(args ...ref.Val) ref.Val {
			state, ok := args[0].Value().(*evaluationContext)
			if !ok {
				return types.NewErr("缺少执行上下文")
			}
			reverse, ok := args[1].Value().(*proto.Reverse)
			if !ok {
				return types.NewErr("反连参数类型无效")
			}
			seconds := int64(args[2].(types.Int))
			if name == "wait" {
				return types.Bool(reverseCheck(state, reverse, seconds))
			}
			return types.Bool(jndiCheck(state, reverse, seconds))
		}))))
	}
	return opts
}
