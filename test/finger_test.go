/*
Package test 指纹与 CEL 集成测试。
*/
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
)

func TestFingerGe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test")
		_, _ = w.Write([]byte("<html><head><title>test</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	target := srv.URL
	proxy := ""
	httpClient := network.NewHTTPClient()
	defer func() { _ = httpClient.Close() }()

	variableMap := map[string]any{}
	customLib := cel.NewCustomLib()

	fin := filepath.Join("..", "fingerYaml", "jiajiu", "0example.yaml")
	fg, err := finger.Read(fin)
	if err != nil {
		t.Fatalf("读取 poc yaml 出错: %v", err)
	}

	variableMap["request"] = finger.TargetRequest(target)

	if len(fg.Set) > 0 {
		finger.IsFuzzSet(fg.Set, variableMap, customLib)
	}

	for _, rule := range fg.Rules {
		opts := network.OptionsRequest{
			Proxy:              proxy,
			Timeout:            10 * time.Second,
			FollowRedirects:    true,
			InsecureSkipVerify: true,
		}
		variableMap, err = finger.SendRequest(context.Background(), httpClient, target, rule.Value.Request, rule.Value, variableMap, opts)
		if err != nil {
			t.Logf("规则 %s 请求失败: %v", rule.Key, err)
			customLib.WriteRuleFunctionsROptions(rule.Key, false)
			continue
		}

		result, err := customLib.Evaluate(rule.Value.Expression, variableMap)
		if err != nil {
			t.Logf("规则 %s CEL 错误: %v", rule.Key, err)
			customLib.WriteRuleFunctionsROptions(rule.Key, false)
			continue
		}
		if result == nil {
			customLib.WriteRuleFunctionsROptions(rule.Key, false)
			continue
		}
		ruleBool, ok := result.Value().(bool)
		if !ok {
			t.Fatalf("规则 %s 结果非 bool", rule.Key)
		}
		customLib.WriteRuleFunctionsROptions(rule.Key, ruleBool)
	}

	final, err := customLib.Evaluate(fg.Expression, variableMap)
	if err != nil {
		t.Fatalf("最终表达式 CEL 错误: %v", err)
	}
	if final == nil {
		t.Fatal("最终表达式结果为空")
	}
	if _, ok := final.Value().(bool); !ok {
		t.Fatal("最终表达式结果非 bool")
	}
}
