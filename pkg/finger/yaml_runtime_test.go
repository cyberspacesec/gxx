package finger

import (
	"fmt"
	"sync"
	"testing"

	"gopkg.in/yaml.v2"
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
