package runner

import (
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"gopkg.in/yaml.v2"
)

func ruleFromYAML(t *testing.T, requestFields string) finger.RuleMap {
	t.Helper()
	var fg finger.Finger
	document := "id: t\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n" + requestFields + "    expression: 'true'\nexpression: r0()\n"
	if err := yaml.Unmarshal([]byte(document), &fg); err != nil {
		t.Fatal(err)
	}
	return fg.Rules[0]
}

// 入口页以"跟随重定向"缓存。默认（未声明/true）的根路径规则必须命中它，
// 显式 false 的规则实际不会跟随，不能误用跟随重定向得到的缓存。
func TestRootRuleCacheLookupMatchesRedirectSemantics(t *testing.T) {
	cm := NewCacheManagerWithBudget(16, time.Minute, 1<<20).newScope()
	defer cm.Close()
	cm.updateOwnedTargetCache(map[string]any{
		"request":  &proto.Request{Method: "GET"},
		"response": &proto.Response{Status: 200},
	}, "http://example.com/", true)

	for _, tc := range []struct {
		name, field string
		wantHit     bool
	}{
		{"未声明", "", true},
		{"true", "      follow_redirects: true\n", true},
		{"false", "      follow_redirects: false\n", false},
	} {
		if hit, _, _ := cm.ShouldUseCache(ruleFromYAML(t, tc.field), "http://example.com/"); hit != tc.wantHit {
			t.Errorf("%s: 缓存命中=%v, want %v", tc.name, hit, tc.wantHit)
		}
	}
}

// 只读取入口页缓存的批量调度路径，不能包含需要独立发起不跟随请求的规则。
func TestOnlyRootRequestsExcludesNonFollowingRules(t *testing.T) {
	build := func(field string) *finger.Finger {
		var fg finger.Finger
		document := "id: t\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n" + field + "    expression: 'true'\nexpression: r0()\n"
		if err := yaml.Unmarshal([]byte(document), &fg); err != nil {
			t.Fatal(err)
		}
		return &fg
	}
	for _, tc := range []struct {
		name, field string
		want        bool
	}{
		{"未声明", "", true},
		{"true", "      follow_redirects: true\n", true},
		{"false", "      follow_redirects: false\n", false},
	} {
		if got := hasOnlyRootRequests(build(tc.field)); got != tc.want {
			t.Errorf("%s: hasOnlyRootRequests=%v, want %v", tc.name, got, tc.want)
		}
	}
}
