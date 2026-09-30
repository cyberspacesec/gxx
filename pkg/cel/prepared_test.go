package cel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	googlecel "github.com/google/cel-go/cel"
)

func TestPreparedLibraryIsolatesEvaluations(t *testing.T) {
	p, err := PrepareLibrary([]string{"r0"}, []string{"r0()"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(want bool) {
			defer wg.Done()
			lib := p.NewEvaluation()
			lib.WriteRuleFunctionsROptions("r0", want)
			for j := 0; j < 20; j++ {
				got, err := lib.Evaluate("r0()", nil)
				if err != nil || got.Value() != want {
					t.Errorf("want=%t got=%v err=%v", want, got, err)
					return
				}
			}
		}(i%2 == 0)
	}
	wg.Wait()
	lib := p.NewEvaluation()
	lib.UpdateCompileOption("value", googlecel.IntType)
	got, err := lib.Evaluate("value == 7 && !r0()", map[string]any{"value": 7})
	if err != nil || got.Value() != true {
		t.Fatalf("动态声明回退失败: %v %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.NewEvaluation().EvaluateContext(ctx, "r0()", nil); err != context.Canceled {
		t.Fatalf("取消未传播: %v", err)
	}
}

func TestPreparedBatchEligibilityExcludesWaitsAndLoops(t *testing.T) {
	for expression, want := range map[string]bool{
		"response.body.bcontains(b'test')": true,
		"sleep(1) == null":                 false,
		"[1, 2].exists(x, x > 0)":          false,
		"proto.Reverse{}.wait(0)":          false,
		"proto.Reverse{}.jndi(0)":          false,
	} {
		plan, err := PrepareLibrary(nil, []string{expression})
		if err != nil {
			t.Fatalf("%s: %v", expression, err)
		}
		if plan.BatchSafe() != want {
			t.Fatalf("%s 批处理条件不正确", expression)
		}
	}
}

func TestReusedEvaluationReleasesPreviousState(t *testing.T) {
	first, err := PrepareLibrary([]string{"old"}, []string{"old()"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareLibrary([]string{"current"}, []string{"current()"})
	if err != nil {
		t.Fatal(err)
	}
	lib := first.NewEvaluation()
	lib.WriteRuleFunctionsROptions("old", true)
	lib.UpdateCompileOption("secret", googlecel.StringType)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lib.SetContext(ctx)
	second.InitEvaluation(lib)
	got, err := lib.Evaluate("current()", nil)
	if err != nil || got.Value() != false {
		t.Fatalf("前次状态泄漏: %v %v", got, err)
	}
	if _, err := lib.Evaluate("old() || secret == 'x'", nil); err == nil {
		t.Fatal("前次声明仍可见")
	}
	lib.Reset()
	if lib.env != nil || lib.prepared != nil || lib.ctx != nil || lib.requests.ctx != nil || lib.activation.variables != nil || len(lib.ruleResults) != 0 {
		t.Fatal("重置后仍持有扫描状态")
	}
	for i := 0; i < 65; i++ {
		lib.WriteRuleFunctionsROptions(fmt.Sprint(i), true)
	}
	lib.Reset()
	if lib.ruleResults != nil {
		t.Fatal("大型规则结果表被保留")
	}
}

func TestComprehensionStillHonorsCancellation(t *testing.T) {
	lib := NewCustomLib()
	lib.UpdateCompileOption("items", googlecel.ListType(googlecel.IntType))
	expression := "items.exists(x, items.exists(y, x + y < 0))"
	if err := lib.Prepare(expression); err != nil {
		t.Fatal(err)
	}
	items := make([]int, 10000)
	for i := range items {
		items[i] = i
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := lib.EvaluateContext(ctx, expression, map[string]any{"items": items})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("循环未按时取消: %v %v", err, time.Since(start))
	}
}
