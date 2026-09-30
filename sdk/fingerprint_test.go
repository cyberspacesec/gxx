package sdk_test

import (
	"context"
	"fmt"
	fy "github.com/cyberspacesec/gxx/fingerYaml"
	gcel "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/sdk"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const positivePage = `<html><head><title>GXX 靶场</title><meta name="generator" content="wordpress 6.0"></head><body><link rel='stylesheet' id='wp-block-library-css' href='/wp-content/themes/t/style.css'><script src='/wp-includes/test.js'></script>Apache2 Ubuntu Default Page: It works</body></html>`

func TestEmbeddedFingerprintsCompile(t *testing.T) {
	rules, err := fy.GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	expressions := 0
	for _, f := range rules {
		if len(f.Set) > 0 || len(f.Payloads.Payloads) > 0 {
			continue
		}
		lib := gcel.NewCustomLib()
		keys := []string{}
		for _, r := range f.Rules {
			keys = append(keys, r.Key)
		}
		lib.PreRegisterRuleFunctions(keys)
		for _, r := range f.Rules {
			expressions++
			if err := lib.Prepare(r.Value.Expression); err != nil {
				t.Errorf("%s/%s: %v", f.Id, r.Key, err)
			}
		}
		expressions++
		if err := lib.Prepare(f.Expression); err != nil {
			t.Errorf("%s final: %v", f.Id, err)
		}
	}
	t.Logf("指纹=%d 表达式=%d", len(rules), expressions)
}
func fullRuleFixture(tb testing.TB, padding int, options ...sdk.Option) (*sdk.Engine, string) {
	tb.Helper()
	body := positivePage + strings.Repeat(" ", padding)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Apache+")
		fmt.Fprint(w, body)
	}))
	tb.Cleanup(s.Close)
	e, err := sdk.NewEngine(context.Background(), append([]sdk.Option{sdk.WithTimeout(5 * time.Second)}, options...)...)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { e.Close() })
	return e, s.URL
}

func TestFullFingerprintParallelParity(t *testing.T) {
	e, target := fullRuleFixture(t, 0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				result, err := e.Scan(context.Background(), target)
				if err != nil {
					t.Error(err)
					return
				}
				ids := make([]string, 0, len(result.Matches))
				for _, match := range result.Matches {
					ids = append(ids, match.Info.ID)
				}
				sort.Strings(ids)
				if fmt.Sprint(ids) != "[apache-detect web-apache-http web-wordpress]" {
					t.Errorf("并行结果不一致: %v", ids)
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkRuleConcurrency(b *testing.B) {
	for _, workers := range []int{8, 32, 64, 200} {
		b.Run(fmt.Sprint(workers), func(b *testing.B) {
			e, target := fullRuleFixture(b, 0, sdk.WithRuleConcurrency(workers))
			if _, err := e.Scan(context.Background(), target); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Scan(context.Background(), target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func TestFullFingerprintPositiveParity(t *testing.T) {
	e, url := fullRuleFixture(t, 0)
	want := []string{"apache-detect", "web-apache-http", "web-wordpress"}
	for i := 0; i < 3; i++ {
		r, err := e.Scan(context.Background(), url)
		if err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, m := range r.Matches {
			got = append(got, m.Info.ID)
		}
		sort.Strings(got)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%v != %v", got, want)
		}
	}
	if e.PoolStats().CompletedTasks != int64(3*e.FingerCount()) {
		t.Fatalf("未遍历所有指纹: %+v", e.PoolStats())
	}
}
func BenchmarkFullFingerprints(b *testing.B) {
	for _, size := range []int{0, 256 << 10} {
		b.Run(fmt.Sprintf("body_%d", size), func(b *testing.B) {
			e, url := fullRuleFixture(b, size)
			if _, err := e.Scan(context.Background(), url); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Scan(context.Background(), url); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
