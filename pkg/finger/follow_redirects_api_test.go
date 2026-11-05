package finger

import (
	"testing"

	"gopkg.in/yaml.v2"
)

func TestRuleRequestShouldFollowRedirects(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       bool
	}{
		{"未声明", "method: GET", true},
		{"true", "follow_redirects: true", true},
		{"false", "follow_redirects: false", false},
	} {
		var request RuleRequest
		if err := yaml.Unmarshal([]byte(tc.yaml), &request); err != nil {
			t.Fatal(err)
		}
		if got := request.ShouldFollowRedirects(); got != tc.want {
			t.Errorf("%s: ShouldFollowRedirects()=%v, want %v", tc.name, got, tc.want)
		}
	}
	// 零值请求（程序化构造、未经过 YAML）同样默认跟随。
	if !(RuleRequest{}).ShouldFollowRedirects() {
		t.Error("零值 RuleRequest 应默认跟随重定向")
	}
}
