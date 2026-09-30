package cel_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	c "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/utils/proto"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRuleResultsStayLocal(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(want bool) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				lib := c.NewCustomLib()
				lib.PreRegisterRuleFunctions([]string{"r0"})
				lib.WriteRuleFunctionsROptions("r0", want)
				v, err := lib.Evaluate("r0()", nil)
				if err != nil || v.Value() != want {
					t.Errorf("want %v got %v, %v", want, v, err)
					return
				}
			}
		}(i%2 == 0)
	}
	wg.Wait()
}
func TestSleepHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	lib := c.NewCustomLib()
	lib.SetContext(ctx)
	start := time.Now()
	_, err := lib.Evaluate("sleep (3600)", nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("elapsed=%v err=%v", time.Since(start), err)
	}
}
func TestInvalidRegexReturnsError(t *testing.T) {
	_, err := c.NewCustomLib().Evaluate(`"[".bmatches(b"text")`, nil)
	if err == nil {
		t.Fatal("invalid regex succeeded")
	}
}
func TestCompactProgramLanguageCompatibility(t *testing.T) {
	for _, expression := range []string{`1 + 2 == 3`, `[1,2,3].all(x,x>0)`, `has({"a":1}.a)`, `"AbC".icontains("bc")`, `b"AbC".ibcontains(b"bc")`, `"(a+)".submatch("aaa")["1"] == "aaa"`, `"x" in ["x","y"]`, `size("abc") == 3`, `int("12") == 12`, `timestamp("2026-01-01T00:00:00Z").getFullYear() == 2026`, `duration("1s") < duration("2s")`} {
		t.Run(expression, func(t *testing.T) {
			v, err := c.NewCustomLib().Evaluate(expression, nil)
			if err != nil || v.Value() != true {
				t.Fatalf("%v %v", v, err)
			}
		})
	}
}
func BenchmarkCachedFingerprintCEL(b *testing.B) {
	response := &proto.Response{Status: 200, Body: []byte(strings.Repeat("body ", 100) + "marker")}
	lib := c.NewCustomLib()
	lib.PreRegisterRuleFunctions([]string{"r0"})
	lib.Prepare(`response.status == 200 && response.body.bcontains(b"marker")`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lib := c.NewCustomLib()
		lib.PreRegisterRuleFunctions([]string{"r0"})
		_, err := lib.Evaluate(`response.status == 200 && response.body.bcontains(b"marker")`, map[string]any{"response": response})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestConcurrentReadOnlyVariables(t *testing.T) {
	variables := map[string]any{"response": &proto.Response{Status: 200}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				v, err := c.NewCustomLib().Evaluate("response.status == 200", variables)
				if err != nil || v.Value() != true {
					t.Errorf("%v %v", v, err)
				}
			}
		}()
	}
	wg.Wait()
	if len(variables) != 1 {
		t.Fatalf("调用方变量被修改: %v", variables)
	}
}
func TestResponseCaseCacheMatchesUnicodeSemantics(t *testing.T) {
	ctx := c.WithResponseCache(context.Background())
	body := []byte(strings.Repeat("字A", 30) + "İKΣς")
	for _, needle := range []string{"字a", "ik", "σς", "nothing"} {
		lib := c.NewCustomLib()
		lib.SetContext(ctx)
		expr := fmt.Sprintf("response.body.ibcontains(bytes(%q))", needle)
		value, err := lib.Evaluate(expr, map[string]any{"response": &proto.Response{Body: body}})
		want := bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(needle)))
		if err != nil || value.Value() != want {
			t.Fatalf("%s %v %v", needle, value, err)
		}
	}
}
