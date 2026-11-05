package utils

import "testing"

// web-Dify 的 r0 要匹配未经跟随的 307 响应，因此必须显式声明 follow_redirects: false；
// r1 依赖跟随重定向后的最终页面。该规则原先按错误的取值含义编写，修正引擎语义时同步翻转，
// 这里防止它被改回而悄悄失效。
func TestDifyRuleRedirectSettings(t *testing.T) {
	rules, err := GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Id != "web-Dify" {
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
	t.Fatal("内置规则库中找不到 web-Dify")
}
