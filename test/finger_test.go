/*
Package test 指纹与 CEL 集成测试。
*/
package main

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	finger2 "github.com/cyberspacesec/gxx/fingerYaml"
	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
)

const embeddedScheme = "embedded://"

func materializeFingerDir(t *testing.T, fingerDir string) string {
	t.Helper()

	if !strings.HasPrefix(fingerDir, embeddedScheme) {
		return fingerDir
	}

	src := filepath.Join("..", "fingerYaml")
	tmpDir := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(tmpDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600)
	})
	if err != nil {
		t.Fatalf("无法展开内置指纹库: %v", err)
	}

	return tmpDir
}

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

	fingerDir := materializeFingerDir(t, finger2.GetFingerPath())
	fin, err := finger.Select(fingerDir, "0example")
	if err != nil {
		t.Fatalf("搜索 poc 文件出错: %v", err)
	}
	fg, err := finger.Read(fin)
	if err != nil {
		t.Fatalf("读取 poc yaml 出错: %v", err)
	}

	tempReq, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("创建临时请求失败: %v", err)
	}
	tempReqData, err := network.ParseRequest(tempReq)
	if err != nil {
		t.Fatalf("解析请求失败: %v", err)
	}
	variableMap["request"] = tempReqData

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
