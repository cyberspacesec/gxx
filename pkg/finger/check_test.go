package finger

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v2"
)

func checkYAML(t *testing.T, data string) []ExpressionError {
	t.Helper()
	var fg Finger
	if err := yaml.Unmarshal([]byte(data), &fg); err != nil {
		t.Fatal(err)
	}
	return CheckExpressions(&fg)
}

func TestCheckExpressions(t *testing.T) {
	const head = "id: demo\ninfo:\n  name: demo\n"
	rule := func(key, expression string) string {
		return "  " + key + ":\n    request:\n      method: GET\n      path: /\n    expression: '" + expression + "'\n"
	}
	if failed := checkYAML(t, head+"rules:\n"+rule("r0", `response.status == 200 && response.body.ibcontains(b"x")`)+rule("r1", `response.headers["server"].contains("nginx")`)+"expression: r0() || r1()\n"); len(failed) != 0 {
		t.Fatalf("合法的指纹被报错: %+v", failed)
	}
	// TLS 指纹变量是响应的字符串字段。
	if failed := checkYAML(t, head+"rules:\n"+rule("r0", `response.tls_version == "TLS 1.2" && response.cipher_suite.startsWith("TLS_") && response.ja3s != "" && response.jarm == ""`)+"expression: r0()\n"); len(failed) != 0 {
		t.Fatalf("TLS 变量被报错: %+v", failed)
	}
	// 语法残缺、未定义的函数、未定义的规则、总表达式残缺。
	failed := checkYAML(t, head+"rules:\n"+rule("r0", `response.status == `)+rule("r1", `response.body.nosuch(b"x")`)+"expression: r0() && r9()\n")
	if len(failed) != 3 || failed[0].Rule != "r0" || failed[1].Rule != "r1" || failed[2].Rule != "" {
		t.Fatalf("应报告 r0、r1 与总表达式: %+v", failed)
	}
	// set / output 变量按任意类型声明，不误报；未声明的变量仍然报错。
	dynamic := head + "set:\n  token: randomLowercase(8)\nrules:\n" +
		"  r0:\n    request:\n      method: GET\n      path: /{{token}}\n    expression: response.body.bcontains(bytes(token))\n    output:\n      version: '\"1\"'\n" +
		rule("r1", `version == "1" && missing == 2`) + "expression: r0()\n"
	failed = checkYAML(t, dynamic)
	if len(failed) != 1 || failed[0].Rule != "r1" || !strings.Contains(failed[0].Err.Error(), "missing") {
		t.Fatalf("只应报告未声明的变量: %+v", failed)
	}
	if failed := checkYAML(t, head+"rules:\n"+rule("r0", "")+"expression: r0()\n"); len(failed) != 1 || failed[0].Rule != "r0" {
		t.Fatalf("空表达式应报错: %+v", failed)
	}
}

func TestCleanTitleDecodesEntities(t *testing.T) {
	if got := cleanTitle("Mail, Sports &amp; Videos &#8211; Yahoo\n"); got != "Mail, Sports & Videos – Yahoo" {
		t.Fatalf("标题中的 HTML 实体未还原: %q", got)
	}
}
