package finger

import (
	"testing"

	celPkg "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/utils/proto"
	"go.yaml.in/yaml/v2"
)

func evalSet(t *testing.T, set yaml.MapSlice) (map[string]any, *celPkg.CustomLib) {
	t.Helper()
	lib := celPkg.NewCustomLib()
	vars := map[string]any{"request": &proto.Request{Url: &proto.UrlType{Scheme: "https", Host: "a.com:8443", Domain: "a.com", Port: "8443", Path: "/x"}}}
	IsFuzzSet(set, vars, lib)
	return vars, lib
}

// YAML 中的非字符串标量（数字、布尔、数字键）不能让类型断言 panic。
func TestIsFuzzSetNonStringScalars(t *testing.T) {
	vars, lib := evalSet(t, yaml.MapSlice{{Key: "n", Value: 5}, {Key: "flag", Value: true}, {Key: 7, Value: "1 + 1"}, {Key: "empty", Value: nil}})
	if vars["n"] != 5 {
		t.Fatalf("n=%#v, want 5", vars["n"])
	}
	if vars["flag"] != "true" {
		t.Fatalf("flag=%#v", vars["flag"])
	}
	if vars["7"] != 2 {
		t.Fatalf("数字键应按文本处理: %#v", vars["7"])
	}
	if out, err := lib.Evaluate("n + 1 == 6", vars); err != nil || out.Value() != true {
		t.Fatalf("n 应声明为 int: %v %v", out, err)
	}
}

// bytes 结果以文本保存，模板中不能出现 "[97 98 99]"。
func TestIsFuzzSetBytesAsText(t *testing.T) {
	vars, _ := evalSet(t, yaml.MapSlice{{Key: "x", Value: `b"abc"`}})
	if vars["x"] != "abc" {
		t.Fatalf("x=%#v, want abc", vars["x"])
	}
	if got := SetVariableMap("/{{x}}", vars); got != "/abc" {
		t.Fatalf("模板替换=%q", got)
	}
}

// URL 对象在 CEL 中可访问字段，在模板中替换为 URL 文本。
func TestIsFuzzSetURLObject(t *testing.T) {
	vars, lib := evalSet(t, yaml.MapSlice{{Key: "u", Value: "request.url"}})
	out, err := lib.Evaluate(`u.host == "a.com:8443" && u.domain == "a.com"`, vars)
	if err != nil || out.Value() != true {
		t.Fatalf("u 应可访问 URL 字段: %v %v", out, err)
	}
	if got := SetVariableMap("{{u}}", vars); got != "https://a.com:8443/x" {
		t.Fatalf("模板替换=%q", got)
	}
}

func TestSetVariableMapSkipsLargeObjects(t *testing.T) {
	vars := map[string]any{"request": &proto.Request{}, "response": &proto.Response{}, "m": map[string]string{"a": "b"}, "s": "v", "i": 3}
	if got := SetVariableMap("{{request}}{{response}}{{m}}{{s}}{{i}}", vars); got != "{{request}}{{response}}{{m}}v3" {
		t.Fatalf("got %q", got)
	}
	if got := SetVariableMap("no template", vars); got != "no template" {
		t.Fatalf("got %q", got)
	}
}
