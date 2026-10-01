/*
  - Package cel
    @Author: zhizhuo
    @IDE：GoLand
    @File: celcompile.go
    @Date: 2025/2/7 上午8:57*
*/
package cel

import (
	"github.com/cyberspacesec/gxx/v2/utils/proto"

	"github.com/google/cel-go/cel"
)

// newEnvOptions 描述只读的 CEL 类型与变量声明，不保存执行者的扫描状态。
var newEnvOptions = []cel.EnvOption{
	cel.Container("proto"),
	cel.Types(
		&proto.UrlType{},
		&proto.Request{},
		&proto.Response{},
		&proto.Reverse{},
	),
	cel.Variable("request", cel.ObjectType("proto.Request")),
	cel.Variable("response", cel.ObjectType("proto.Response")),
}

// ReadCompileOptions 返回 CEL 环境选项（类型、变量、函数实现）
func ReadCompileOptions() []cel.EnvOption {
	allEnvOptions := make([]cel.EnvOption, 0, len(newEnvOptions)+len(functionEnvOptions))
	allEnvOptions = append(allEnvOptions, newEnvOptions...)
	allEnvOptions = append(allEnvOptions, functionEnvOptions...)
	return append(allEnvOptions, contextEnvOptions()...)
}
