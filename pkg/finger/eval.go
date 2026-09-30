/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: eval.go
    @Date: 2025/2/21 下午3:01*
*/
package finger

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v2"

	celPkg "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/proto"
)

// IsFuzzSet 解析Set中的定义变量
func IsFuzzSet(args yaml.MapSlice, variableMap map[string]any, customLib *celPkg.CustomLib) {
	for _, arg := range args {
		key := arg.Key.(string)
		value := arg.Value.(string)
		if value == "newReverse()" {
			variableMap[key] = newReverse(customLib.ReverseConfig())
			customLib.UpdateCompileOption(key, cel.ObjectType("proto.Reverse"))
			continue
		}
		if value == "newJNDI()" {
			variableMap[key] = newJNDI(customLib.ReverseConfig())
			customLib.UpdateCompileOption(key, cel.ObjectType("proto.Reverse"))
			continue
		}

		out, err := customLib.Evaluate(value, variableMap)
		if err != nil {
			variableMap[key] = fmt.Sprintf("%v", value)
			customLib.UpdateCompileOption(key, cel.StringType)
			continue
		}
		switch value := out.Value().(type) {
		case *proto.UrlType:
			variableMap[key] = common.UrlTypeToString(value)
			customLib.UpdateCompileOption(key, cel.ObjectType("proto.UrlType"))
		case int64:
			variableMap[key] = int(value)
			customLib.UpdateCompileOption(key, cel.IntType)
		case map[string]string:
			variableMap[key] = value
			customLib.UpdateCompileOption(key, cel.MapType(cel.StringType, cel.StringType))
		default:
			variableMap[key] = fmt.Sprintf("%v", out)
			customLib.UpdateCompileOption(key, cel.StringType)
		}
	}
}

// SetVariableMap 处理解析set中变量
// 跳过 proto.Request/Response/Reverse 等不可能出现在模板中的大对象，
// 避免 fmt.Sprintf("%v") 触发 protobuf 文本序列化（单次数百KB，占总分配64%）
func SetVariableMap(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		switch v.(type) {
		case map[string]string, *proto.Request, *proto.Response, *proto.Reverse, *proto.UrlType:
			continue
		}
		oldStr := "{{" + k + "}}"
		if !strings.Contains(find, oldStr) {
			continue
		}
		find = strings.ReplaceAll(find, oldStr, fmt.Sprintf("%v", v))
	}
	return find
}

func newReverse(config types.ReverseConfig) *proto.Reverse {
	sub := common.RandomString(12)
	urlStr := fmt.Sprintf("http://%s.%s", sub, config.CeyeDomain)
	u, err := url.Parse(urlStr)
	if err != nil {
		return &proto.Reverse{Url: &proto.UrlType{}}
	}
	return &proto.Reverse{
		Url:                common.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

func newJNDI(config types.ReverseConfig) *proto.Reverse {
	randomStr := common.RandomString(22)
	urlStr := "http://" + net.JoinHostPort(config.JNDIHost, config.LDAPPort) + "/" + randomStr
	u, err := url.Parse(urlStr)
	if err != nil {
		return &proto.Reverse{Url: &proto.UrlType{}}
	}
	parseUrl := common.ParseUrl(u)
	return &proto.Reverse{
		Url:                parseUrl,
		Domain:             u.Hostname(),
		Ip:                 config.JNDIHost,
		IsDomainNameServer: false,
	}
}
