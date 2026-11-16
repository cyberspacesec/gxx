package finger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v2"
)

func TestConcurrentYAMLParsesKeepIndependentOrder(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 24; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				document := fmt.Sprintf("rules:\n  z:\n    expression: old\n  a:\n    expression: middle\n  z:\n    expression: worker-%d\n", worker)
				var fg Finger
				if err := yaml.Unmarshal([]byte(document), &fg); err != nil {
					t.Error(err)
					return
				}
				if len(fg.Rules) != 2 || fg.Rules[0].Key != "a" || fg.Rules[1].Key != "z" || fg.Rules[1].Value.Expression != fmt.Sprintf("worker-%d", worker) {
					t.Errorf("并发加载串用了规则: %+v", fg.Rules)
				}
				var direct Rule
				if err := yaml.Unmarshal([]byte("expression: direct\n"), &direct); err != nil || direct.Expression != "direct" {
					t.Errorf("独立规则解析失败: %+v %v", direct, err)
				}
			}
		}(worker)
	}
	wg.Wait()
}

func TestYAMLRuleFieldsAndSourceOrder(t *testing.T) {
	var fg Finger
	document := "rules:\n  second:\n    request:\n      method: GET\n      path: /test\n      headers:\n        X-Test: configured\n    expression: first\n    output:\n      value: result\n  first:\n    expression: last\n"
	if err := yaml.Unmarshal([]byte(document), &fg); err != nil {
		t.Fatal(err)
	}
	if len(fg.Rules) != 2 || fg.Rules[0].Key != "second" || fg.Rules[1].Key != "first" {
		t.Fatalf("源文件顺序不一致: %+v", fg.Rules)
	}
	r := fg.Rules[0].Value
	if r.Request.Method != "GET" || r.Request.Path != "/test" || r.Request.Headers["X-Test"] != "configured" || r.Expression != "first" || len(r.Output) != 1 || r.Output[0].Key != "value" || r.Output[0].Value != "result" {
		t.Fatalf("规则字段丢失: %+v", r)
	}
}

// TestRuleTypeNormalizedAndValidatedAtLoad 锁定传输类型在加载期归一化并校验。
//
// 回归点一：`type: HTTP` 大小写不一致时，IsHTTPType 判定为非 HTTP 规则（跳过
// 探活、也不计入 HTTP 规则），但执行路径又按 HTTP 走，两处判断自相矛盾。
// 回归点二：未知类型（如 type: ssl）原先落到 HTTP 分支静默降级成明文请求并
// "命中"，掩盖规则错误；改成执行期报错后仍只打一行 Debug 日志，默认日志级别
// 下看不见，且每个目标都会白耗一个限流令牌。校验前移到加载期才能真正暴露。
func TestRuleTypeNormalizedAndValidatedAtLoad(t *testing.T) {
	write := func(t *testing.T, ruleType string) (*Finger, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "rule.yaml")
		data := "id: t\ninfo:\n  name: t\nrules:\n  r0:\n    request:\n      type: " +
			ruleType + "\n      method: GET\n      path: /\n    expression: true\nexpression: r0()\n"
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		return Read(path)
	}

	t.Run("大小写归一化且计入HTTP", func(t *testing.T) {
		for _, raw := range []string{"HTTP", "Http", " http "} {
			fg, err := write(t, raw)
			if err != nil {
				t.Fatalf("%q 被拒绝: %v", raw, err)
			}
			if got := fg.Rules[0].Value.Request.Type; got != HttpType {
				t.Errorf("%q 未归一化: Type=%q", raw, got)
			}
			if !fg.IsHTTPType() {
				t.Errorf("%q 未被计入 HTTP 规则，会跳过探活", raw)
			}
		}
	})

	t.Run("tcp与udp保留并排除HTTP", func(t *testing.T) {
		for _, raw := range []string{"TCP", "udp"} {
			fg, err := write(t, raw)
			if err != nil {
				t.Fatalf("%q 被拒绝: %v", raw, err)
			}
			if got, want := fg.Rules[0].Value.Request.Type, strings.ToLower(raw); got != want {
				t.Errorf("%q 归一化错误: Type=%q 期望 %q", raw, got, want)
			}
			if fg.IsHTTPType() {
				t.Errorf("%q 被误判为 HTTP 规则", raw)
			}
		}
	})

	t.Run("未知类型在加载期被拒绝", func(t *testing.T) {
		for _, raw := range []string{"ssl", "tls", "grpc", "go"} {
			if _, err := write(t, raw); err == nil {
				t.Errorf("type: %s 未在加载期被拒绝，会静默降级成明文 HTTP", raw)
			}
		}
	})
}
