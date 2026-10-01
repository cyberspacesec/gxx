package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	celpkg "github.com/cyberspacesec/gxx/pkg/cel"
	fingerpkg "github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/proto"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
)

// FingerService 逐 rule 运行指纹并提供 CEL 调试能力。
type FingerService struct{}

// NewFingerService 返回 FingerService。
func NewFingerService() *FingerService { return &FingerService{} }

// Run 逐 rule 运行指纹并返回 IDE 调试面板所需的中间结果。
func (s *FingerService) Run(ctx context.Context, in *model.RunFingerprintInput) (*model.RunFingerprintOutput, error) {
	if in == nil {
		return nil, response.NewBadRequest("缺少请求参数")
	}
	if strings.TrimSpace(in.YAML) == "" {
		return nil, response.NewBadRequest("YAML 内容为空")
	}
	if strings.TrimSpace(in.Target) == "" {
		return nil, response.NewBadRequest("目标 URL 不能为空")
	}

	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var fg fingerpkg.Finger
	if err := yaml.Unmarshal([]byte(in.YAML), &fg); err != nil {
		return nil, response.NewBadRequest(err.Error())
	}

	customLib := celpkg.NewCustomLib()
	customLib.SetContext(ctx)
	varMap := map[string]any{}
	if len(fg.Set) > 0 {
		fingerpkg.IsFuzzSet(fg.Set, varMap, customLib)
	}
	if len(fg.Payloads.Payloads) > 0 {
		fingerpkg.IsFuzzSet(fg.Payloads.Payloads, varMap, customLib)
	}

	ruleKeys := make([]string, 0, len(fg.Rules))
	for _, rule := range fg.Rules {
		if rule.Key != "" {
			ruleKeys = append(ruleKeys, rule.Key)
		}
	}
	customLib.PreRegisterRuleFunctions(ruleKeys)

	client := network.NewHTTPClient()
	defer client.Close()
	client.SetInsecureSkipVerify(!in.VerifyTLS)
	customLib.SetRequestOptions(client, network.OptionsRequest{Proxy: in.Proxy, Timeout: timeout, InsecureSkipVerify: !in.VerifyTLS, FollowRedirects: in.FollowRedirects})

	out := &model.RunFingerprintOutput{
		FinalExpression: fg.Expression,
		Rules:           make([]model.RuleRun, 0, len(fg.Rules)),
	}
	if outline := BuildOutlineFromYAML(in.YAML); outline != nil {
		out.FingerOutline = outline
	}

	for _, rule := range fg.Rules {
		reqCopy := rule.Value.Request
		if len(reqCopy.Headers) > 0 {
			headers := make(map[string]string, len(reqCopy.Headers))
			for key, value := range reqCopy.Headers {
				headers[key] = value
			}
			reqCopy.Headers = headers
		}
		reqCopy.Path = fingerpkg.SetVariableMap(strings.TrimSpace(reqCopy.Path), varMap)

		ruleCopy := rule
		ruleCopy.Value.Request = reqCopy
		record := model.RuleRun{
			Key:          ruleCopy.Key,
			Expression:   ruleCopy.Value.Expression,
			Method:       firstNonEmpty(reqCopy.Method, "GET"),
			Path:         reqCopy.Path,
			URLEvaluated: buildEvaluatedURL(in.Target, reqCopy.Path),
		}

		nextVarMap, err := fingerpkg.SendRequest(ctx, client, in.Target, reqCopy, ruleCopy.Value, varMap, network.OptionsRequest{
			Proxy:              in.Proxy,
			Timeout:            timeout,
			FollowRedirects:    in.FollowRedirects,
			InsecureSkipVerify: !in.VerifyTLS,
		})
		if err != nil {
			record.HTTPError = err.Error()
			customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
			out.Rules = append(out.Rules, record)
			continue
		}
		if len(nextVarMap) > 0 {
			varMap = nextVarMap
		}

		if req, ok := varMap["request"].(*proto.Request); ok {
			record.RequestRaw = string(req.GetRaw())
			if record.RequestRaw == "" {
				record.RequestRaw = string(req.GetRawHeader())
			}
		}
		if resp, ok := varMap["response"].(*proto.Response); ok {
			record.ResponseRaw = string(resp.GetRaw())
			if record.ResponseRaw == "" {
				record.ResponseRaw = string(resp.GetRawHeader())
			}
			record.StatusCode = resp.GetStatus()
			record.Latency = resp.GetLatency()
		}

		result, evalErr := customLib.Evaluate(ruleCopy.Value.Expression, varMap)
		if evalErr != nil {
			record.CELError = evalErr.Error()
			customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
		} else if rb, ok := result.Value().(bool); ok {
			record.Result = rb
			customLib.WriteRuleFunctionsROptions(ruleCopy.Key, rb)
		} else {
			record.NonBoolResult = true
			customLib.WriteRuleFunctionsROptions(ruleCopy.Key, false)
		}
		if record.Result && len(ruleCopy.Value.Output) > 0 {
			fingerpkg.EvaluateOutput(ruleCopy.Value.Output, varMap, customLib)
		}
		out.Rules = append(out.Rules, record)
	}

	finalExpression := strings.TrimSpace(fg.Expression)
	if finalExpression == "" && len(ruleKeys) > 0 {
		finalExpression = ruleKeys[0] + "()"
		out.FinalExpression = finalExpression
	}
	if finalExpression != "" {
		result, err := customLib.Evaluate(finalExpression, varMap)
		if err != nil {
			out.ExpressionError = err.Error()
		} else if rb, ok := result.Value().(bool); ok {
			out.FinalResult = rb
		} else {
			out.ExpressionError = fmt.Sprintf("最终表达式返回非布尔值: %T", result.Value())
		}
	}
	out.Variables = debugVarEntries(varMap)
	return out, nil
}

func (s *FingerService) EvaluateCELContext(ctx context.Context, in *model.EvaluateCELInput) (*model.EvaluateCELOutput, error) {
	if in == nil {
		return nil, response.NewBadRequest("缺少请求参数")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	customLib := celpkg.NewCustomLib()
	customLib.SetContext(ctx)
	vars := normalizeCELVariables(in.Variables)
	result, err := customLib.Evaluate(in.Expression, vars)
	if err != nil {
		return nil, response.NewBadRequest(err.Error())
	}
	return &model.EvaluateCELOutput{
		Result: fmt.Sprintf("%v", result.Value()),
		Type:   string(result.Type().TypeName()),
	}, nil
}

func buildEvaluatedURL(target, path string) string {
	if strings.TrimSpace(path) == "" {
		return target
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(target, "/") + "/" + strings.TrimLeft(path, "/")
}

func debugVarEntries(varMap map[string]any) []model.VarEntry {
	keys := make([]string, 0, len(varMap))
	for key := range varMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.VarEntry, 0, len(keys))
	for _, key := range keys {
		value := varMap[key]
		out = append(out, model.VarEntry{
			Key:   key,
			Type:  fmt.Sprintf("%T", value),
			Value: debugValueString(value),
		})
	}
	return out
}

func debugValueString(value any) string {
	switch v := value.(type) {
	case *proto.Request:
		if raw := strings.TrimSpace(string(v.GetRaw())); raw != "" {
			return raw
		}
		return fmt.Sprintf("%s %s", v.GetMethod(), v.GetUrl())
	case *proto.Response:
		if raw := strings.TrimSpace(string(v.GetRawHeader())); raw != "" {
			return raw
		}
		return fmt.Sprintf("status=%d body=%d bytes", v.GetStatus(), len(v.GetBody()))
	default:
		return fmt.Sprintf("%v", value)
	}
}

func normalizeCELVariables(vars map[string]any) map[string]any {
	out := make(map[string]any, len(vars))
	for key, value := range vars {
		switch key {
		case "response":
			if rec, ok := value.(map[string]any); ok {
				out[key] = mapToProtoResponse(rec)
				continue
			}
		case "request":
			if rec, ok := value.(map[string]any); ok {
				out[key] = mapToProtoRequest(rec)
				continue
			}
		}
		out[key] = value
	}
	return out
}

func mapToProtoResponse(rec map[string]any) *proto.Response {
	resp := &proto.Response{Headers: mapStringAny(rec["headers"])}
	if status, ok := numberToInt32(rec["status"]); ok {
		resp.Status = status
	}
	resp.Body = []byte(fmt.Sprintf("%v", rec["body"]))
	resp.Raw = []byte(fmt.Sprintf("%v", rec["raw"]))
	resp.RawHeader = []byte(fmt.Sprintf("%v", rec["raw_header"]))
	return resp
}

func mapToProtoRequest(rec map[string]any) *proto.Request {
	req := &proto.Request{Headers: mapStringAny(rec["headers"])}
	req.Method = fmt.Sprintf("%v", rec["method"])
	req.Body = []byte(fmt.Sprintf("%v", rec["body"]))
	req.Raw = []byte(fmt.Sprintf("%v", rec["raw"]))
	req.RawHeader = []byte(fmt.Sprintf("%v", rec["raw_header"]))
	return req
}

func mapStringAny(value any) map[string]string {
	out := map[string]string{}
	rec, ok := value.(map[string]any)
	if !ok {
		return out
	}
	for key, val := range rec {
		out[strings.ToLower(key)] = fmt.Sprintf("%v", val)
	}
	return out
}

func numberToInt32(value any) (int32, bool) {
	switch v := value.(type) {
	case float64:
		return int32(v), true
	case int:
		return int32(v), true
	case int32:
		return v, true
	default:
		return 0, false
	}
}

// BuildOutlineFromYAML 从 YAML 解析 outline（供 Run 输出元信息）。
func BuildOutlineFromYAML(yamlContent string) *model.FingerOutline {
	out := NewYamlService().Validate(yamlContent)
	if out == nil || out.Outline == nil {
		return nil
	}
	return out.Outline
}
