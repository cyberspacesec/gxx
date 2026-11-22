package sdk_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/cyberspacesec/gxx/sdk"
)

const policyHead = "id: demo\ninfo:\n  name: demo\n"

// demoProduct 是标准格式要求的产品声明。
const demoProduct = "  product:\n    id: acme.demo\n    name: Demo\n    category: application\n    identity: product\n    assurance: inferred\n"

func httpSubRule(key, expression string) string {
	return "  " + key + ":\n    request:\n      method: GET\n      path: /\n    expression: " + expression + "\n"
}

var policyCorpus = map[string]string{
	"plain":    policyHead + "rules:\n" + httpSubRule("r0", "response.status == 200") + "expression: r0()\n",
	"tcp":      policyHead + "rules:\n  r0:\n    request:\n      type: tcp\n      host: 127.0.0.1:22\n      data: ping\n    expression: response.raw.bcontains(b\"SSH\")\nexpression: r0()\n",
	"raw":      policyHead + "rules:\n  r0:\n    request:\n      raw: |\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n\n    expression: response.status == 200\nexpression: r0()\n",
	"reverse":  policyHead + "set:\n  reverse: newReverse()\nrules:\n" + httpSubRule("r0", "reverse.wait(5)") + "expression: r0()\n",
	"jndi":     policyHead + "rules:\n" + httpSubRule("r0", "response.status == 200") + "expression: r0() && jndiHost.jndi(3)\nset:\n  jndiHost: newJNDI()\n",
	"sleep":    policyHead + "rules:\n" + httpSubRule("r0", "sleep(1) == null || response.status == 200") + "expression: r0()\n",
	"output":   policyHead + "rules:\n" + httpSubRule("r0", "response.status == 200") + "    output:\n      product_version: '\"1\" + string(sleep(0))'\nexpression: r0()\n",
	"many":     policyHead + "rules:\n" + httpSubRule("r0", "true") + httpSubRule("r1", "true") + httpSubRule("r2", "true") + "expression: r0()\n",
	"badtype":  policyHead + "rules:\n  r0:\n    request:\n      type: ftp\n    expression: 'true'\nexpression: r0()\n",
	"syntax":   policyHead + "rules:\n  r0:\n    request: [\n",
	"badexpr":  policyHead + "rules:\n" + httpSubRule("r0", "'response.status == '") + "expression: r0()\n",
	"unknown":  "id: demo\ninfo:\n  name: demo\n  vendorr: x\nrules:\n" + httpSubRule("r0", "true") + "expression: r0()\n",
	"noname":   "id: demo\nrules:\n" + httpSubRule("r0", "true") + "expression: r0()\n",
	"typo":     policyHead + "rules:\n  r0:\n    request:\n      method: GET\n      path: /\n      follow_redirect: false\n    expression: 'true'\nexpression: r0()\ntransprot: http\n",
	"empty":    "",
	"sequence": "- a\n- b\n",
	"badid":    "id: Web_Demo\ninfo:\n  name: demo\n" + demoProduct + "rules:\n" + httpSubRule("r0", "true") + "expression: r0()\n",
	"product":  "id: demo\ninfo:\n  name: demo\n  product:\n    id: Demo\n    name: demo\n    category: portal\n    identity: product\n    assurance: verified\nrules:\n" + httpSubRule("r0", "true") + "expression: r0()\n",
}

var policyCases = []sdk.RulePolicy{
	{},
	{AllowTypes: []string{"http"}},
	{AllowTypes: []string{"http", "tcp", "udp"}, AllowRaw: true},
	{AllowTypes: []string{"HTTP", "TCP"}, AllowReverse: true, AllowSleep: true},
	{MaxSubRules: 2},
	{AllowRaw: true, AllowReverse: true, AllowSleep: true, MaxSubRules: 1},
}

func hasError(diagnostics []sdk.Diagnostic) bool {
	for _, d := range diagnostics {
		if d.Severity == "error" {
			return true
		}
	}
	return false
}

// ValidateRule（非严格）与 NewEngine 的结论一致：有 error 当且仅当引擎拒绝加载。
func TestValidateRuleAgreesWithNewEngine(t *testing.T) {
	for name, content := range policyCorpus {
		for _, policy := range policyCases {
			diagnostics := sdk.ValidateRule([]byte(content), sdk.ValidateOptions{Policy: policy})
			e, err := sdk.NewEngine(context.Background(), sdk.WithRuleFS(fstest.MapFS{"rule.yaml": {Data: []byte(content)}}, "."), sdk.WithRulePolicy(policy))
			if err == nil {
				_ = e.Close()
			}
			if hasError(diagnostics) != (err != nil) {
				t.Fatalf("%s %+v: 校验=%+v 引擎=%v", name, policy, diagnostics, err)
			}
			if err != nil && strings.HasPrefix(diagnostics[0].Code, "policy-") && !errors.Is(err, sdk.ErrRulePolicy) {
				t.Fatalf("%s: 策略错误应可用 ErrRulePolicy 判断: %v", name, err)
			}
		}
	}
}

// 规则策略：被禁用的类型、raw、反连与 sleep 以及子规则数上限都在加载时报错，
// 错误含规则标识与字段；校验给出相同字段与行号。
func TestRulePolicyViolations(t *testing.T) {
	cases := []struct {
		name, corpus string
		policy       sdk.RulePolicy
		field, code  string
		line         int
	}{
		{"type", "tcp", sdk.RulePolicy{AllowTypes: []string{"http"}}, "rules.r0.request.type", "policy-type", 7},
		{"raw", "raw", sdk.RulePolicy{AllowTypes: []string{"http"}}, "rules.r0.request.raw", "policy-raw", 7},
		{"reverse-set", "reverse", sdk.RulePolicy{AllowSleep: true}, "set.reverse", "policy-reverse", 5},
		{"reverse-wait", "reverse", sdk.RulePolicy{AllowSleep: true}, "rules.r0.expression", "policy-reverse", 11},
		{"jndi", "jndi", sdk.RulePolicy{AllowSleep: true}, "expression", "policy-reverse", 10},
		{"sleep", "sleep", sdk.RulePolicy{AllowReverse: true}, "rules.r0.expression", "policy-sleep", 9},
		{"sleep-output", "output", sdk.RulePolicy{AllowReverse: true}, "rules.r0.output.product_version", "policy-sleep", 11},
		{"sub-rules", "many", sdk.RulePolicy{MaxSubRules: 2}, "rules", "policy-sub-rules", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := policyCorpus[tc.corpus]
			_, err := sdk.NewEngine(context.Background(), sdk.WithRuleFS(fstest.MapFS{"rule.yaml": {Data: []byte(content)}}, "."), sdk.WithRulePolicy(tc.policy))
			var violation *sdk.RulePolicyError
			if !errors.Is(err, sdk.ErrRulePolicy) || !errors.As(err, &violation) || violation.RuleID != "demo" || !strings.Contains(err.Error(), "demo") {
				t.Fatalf("err=%v", err)
			}
			var found *sdk.Diagnostic
			for _, d := range sdk.ValidateRule([]byte(content), sdk.ValidateOptions{Policy: tc.policy}) {
				if d.Code == tc.code && d.Field == tc.field {
					d := d
					found = &d
				}
			}
			if found == nil || found.Severity != "error" || found.Line != tc.line {
				t.Fatalf("诊断=%+v，期望 %s %s 第 %d 行", found, tc.code, tc.field, tc.line)
			}
		})
	}
	// 规则数上限只在加载规则库时检查。
	library := fstest.MapFS{"a.yaml": {Data: []byte(policyCorpus["plain"])}, "b.yaml": {Data: []byte(strings.Replace(policyCorpus["plain"], "id: demo", "id: other", 1))}}
	if _, err := sdk.NewEngine(context.Background(), sdk.WithRuleFS(library, "."), sdk.WithRulePolicy(sdk.RulePolicy{MaxRules: 1})); !errors.Is(err, sdk.ErrRulePolicy) {
		t.Fatalf("超过规则数上限应报错: %v", err)
	}
	// 内置规则库只有 HTTP 规则，不使用 raw、反连与 sleep。
	e, err := sdk.NewEngine(context.Background(), sdk.WithRulePolicy(sdk.RulePolicy{AllowTypes: []string{"http"}}))
	if err != nil {
		t.Fatalf("内置规则库应满足仅 HTTP 的策略: %v", err)
	}
	_ = e.Close()
}

// 重新加载同样受规则策略约束，失败时保留原规则集。
func TestRulePolicyOnReload(t *testing.T) {
	e := newRuleEngine(t, map[string]string{"plain": policyCorpus["plain"]}, sdk.WithRulePolicy(sdk.RulePolicy{AllowTypes: []string{"http"}}))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tcp.yaml"), []byte(policyCorpus["tcp"]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.LoadFingerOptions(sdk.FingerOptions{PocFile: dir}); !errors.Is(err, sdk.ErrRulePolicy) || !errors.Is(err, sdk.ErrLoadFinger) {
		t.Fatalf("err=%v", err)
	}
	if e.FingerCount() != 1 {
		t.Fatalf("失败的重新加载不应替换规则集: %d", e.FingerCount())
	}
}

// 严格模式把规范性问题报告为 error，非严格模式为 warning；语法错误给出行号。
func TestValidateRuleStrictness(t *testing.T) {
	cases := []struct {
		corpus, code, field string
		line                int
	}{
		{"unknown", "unknown-key", "info.vendorr", 4},
		{"noname", "missing-name", "info.name", 0},
		{"badexpr", "expression-compile", "rules.r0.expression", 9},
		{"typo", "unknown-key", "rules.r0.request.follow_redirect", 9},
		{"plain", "missing-product", "info.product", 2},
		{"badid", "invalid-id", "id", 1},
		{"product", "invalid-product", "info.product.id", 5},
		{"product", "invalid-product", "info.product.category", 7},
		{"product", "invalid-product", "info.product.references", 4},
	}
	for _, tc := range cases {
		for _, strict := range []bool{false, true} {
			var found *sdk.Diagnostic
			for _, d := range sdk.ValidateRule([]byte(policyCorpus[tc.corpus]), sdk.ValidateOptions{Strict: strict}) {
				if d.Code == tc.code && d.Field == tc.field {
					d := d
					found = &d
				}
			}
			want := map[bool]string{false: "warning", true: "error"}[strict]
			if found == nil || found.Severity != want || found.Field != tc.field || found.Line != tc.line {
				t.Fatalf("%s strict=%v: %+v", tc.corpus, strict, found)
			}
		}
	}
	syntax := sdk.ValidateRule([]byte(policyCorpus["syntax"]), sdk.ValidateOptions{})
	if len(syntax) != 1 || syntax[0].Code != "yaml" || syntax[0].Severity != "error" || syntax[0].Line == 0 {
		t.Fatalf("%+v", syntax)
	}
	badType := sdk.ValidateRule([]byte(policyCorpus["badtype"]), sdk.ValidateOptions{})
	if len(badType) != 1 || badType[0].Code != "yaml" || badType[0].Field != "rules.r0.request.type" || badType[0].Line != 7 {
		t.Fatalf("%+v", badType)
	}
	var unknown []sdk.Diagnostic
	for _, d := range sdk.ValidateRule([]byte(policyCorpus["typo"]), sdk.ValidateOptions{}) {
		if d.Code == "unknown-key" {
			unknown = append(unknown, d)
		}
	}
	if len(unknown) != 2 || unknown[1].Field != "transprot" || unknown[1].Line != 12 {
		t.Fatalf("每个未知键各报一次: %+v", unknown)
	}
	standard := strings.Replace(policyCorpus["plain"], "  name: demo\n", "  name: demo\n"+demoProduct, 1)
	if got := sdk.ValidateRule([]byte(standard), sdk.ValidateOptions{Strict: true}); len(got) != 0 {
		t.Fatalf("合规的规则不应有诊断: %+v", got)
	}
}

// 内置规则库的每个文件都通过严格校验。
func TestBuiltinRulesPassStrictValidation(t *testing.T) {
	library := os.DirFS(filepath.Join("..", "fingerYaml"))
	files := 0
	err := fs.WalkDir(library, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return err
		}
		files++
		data, err := fs.ReadFile(library, path)
		if err != nil {
			return err
		}
		for _, diagnostic := range sdk.ValidateRule(data, sdk.ValidateOptions{Strict: true}) {
			t.Errorf("%s: %+v", path, diagnostic)
		}
		return nil
	})
	if err != nil || files == 0 {
		t.Fatalf("files=%d err=%v", files, err)
	}
}
