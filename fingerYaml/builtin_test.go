package utils

import (
	"testing"

	finger2 "github.com/cyberspacesec/gxx/pkg/finger"
)

// langgenius-dify 的 r0 要匹配未经跟随的 307 响应，因此必须显式声明 follow_redirects: false；
// r1 依赖跟随重定向后的最终页面。该规则原先按错误的取值含义编写，修正引擎语义时同步翻转，
// 这里防止它被改回而悄悄失效。
func TestDifyRuleRedirectSettings(t *testing.T) {
	rules, err := GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Id != "langgenius-dify" {
			continue
		}
		if len(rule.Rules) != 2 {
			t.Fatalf("规则数量变化: %d", len(rule.Rules))
		}
		if request := rule.Rules[0].Value.Request; request.ShouldFollowRedirects() {
			t.Error("r0 匹配 307 响应，必须声明 follow_redirects: false")
		}
		if request := rule.Rules[1].Value.Request; !request.ShouldFollowRedirects() {
			t.Error("r1 依赖跟随重定向后的页面，必须跟随重定向")
		}
		return
	}
	t.Fatal("内置规则库中找不到 langgenius-dify")
}

// 内置规则库里每条表达式都必须能编译：加载时编译失败的指纹会退回逐条动态求值，
// 表达式写错不会报错，只会永远不命中。
func TestBuiltinExpressionsCompile(t *testing.T) {
	rules, err := GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		for _, failed := range finger2.CheckExpressions(rule) {
			t.Errorf("%s 规则 %q 的表达式 %q 编译失败: %v", rule.Id, failed.Rule, failed.Expression, failed.Err)
		}
	}
}
