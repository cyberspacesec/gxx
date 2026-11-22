package sdk_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// subRuleRule 生成一条子规则请求 path 的规则，可附带输出提取。
func subRuleRule(id, path, expression, output string) string {
	rule := "id: " + id + "\ninfo:\n  name: " + id + "\nrules:\n  r0:\n    request:\n      method: GET\n      path: " + path + "\n    expression: '" + expression + "'\n"
	if output != "" {
		rule += "    output:\n      product_version: '" + output + "'\n"
	}
	return rule + "expression: r0()\n"
}

// reportServer 提供各种求值失败场景需要的页面。
func reportServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hangup":
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		case "/backtrack":
			_, _ = w.Write([]byte(strings.Repeat("a", 64) + "!"))
		default:
			w.Header().Set("Server", "demo")
			_, _ = w.Write([]byte("<html>welcome page</html>"))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func failureStages(rule sdk.RuleEvaluation) []sdk.FailureStage {
	var stages []sdk.FailureStage
	for _, failure := range rule.Failures {
		stages = append(stages, failure.Stage)
	}
	return stages
}

func findRule(report sdk.EvaluationReport, id string) (sdk.RuleEvaluation, bool) {
	for _, rule := range report.Rules {
		if rule.RuleID == id {
			return rule, true
		}
	}
	return sdk.RuleEvaluation{}, false
}

// 每种失败都使报告不完整并给出对应阶段；带报告与不带报告的扫描命中结果相同。
func TestEvaluationReportStages(t *testing.T) {
	server := reportServer(t)
	many := "id: many\ninfo:\n  name: many\nrules:\n"
	for i := 0; i < 17; i++ {
		many += fmt.Sprintf("  r%d:\n    request:\n      method: GET\n      path: /\n    expression: 'response.headers[\"missing-%d\"] == \"x\"'\n", i, i)
	}
	many += "expression: r0()\n"
	cases := []struct {
		name  string
		rule  string
		stage sdk.FailureStage
		opts  []sdk.Option
	}{
		{"expression", subRuleRule("rule", "/", `response.headers["missing"] == "x"`, ""), sdk.StageExpression, nil},
		{"non_bool", subRuleRule("rule", "/", `response.status`, ""), sdk.StageNonBool, nil},
		{"extract", subRuleRule("rule", "/", `response.body.bcontains(b"welcome")`, `"v(?P<version>[0-9.]+)".bsubmatch(response.body)["version"]`), sdk.StageExtract, nil},
		{"regex_timeout", subRuleRule("rule", "/backtrack", `"(a+)+$".bmatches(response.body)`, ""), sdk.StageRegexTimeout, nil},
		{"request", subRuleRule("rule", "/hangup", `response.status == 200`, ""), sdk.StageRequest, nil},
		{"budget", subRuleRule("rule", "/", `response.body.bcontains(b"welcome")`, ""), sdk.StageBudget, []sdk.Option{sdk.WithBodyLimit(8)}},
		{"records", many, sdk.StageBudget, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := "rule"
			if tc.name == "records" {
				id = "many"
			}
			e := newRuleEngine(t, map[string]string{id: tc.rule, "ok": exprRule("ok", `response.status == 200`)}, tc.opts...)
			plain, err := e.Scan(context.Background(), server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var report sdk.EvaluationReport
			reported, err := e.ScanWith(context.Background(), server.URL, sdk.ScanEvaluationReport(&report))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(resultIDs(plain), resultIDs(reported)) {
				t.Fatalf("报告改变了命中结果: %v != %v", resultIDs(plain), resultIDs(reported))
			}
			rule, found := findRule(report, id)
			if report.Complete || !found || rule.Completed || !slices.Contains(failureStages(rule), tc.stage) {
				t.Fatalf("complete=%v rule=%+v", report.Complete, rule)
			}
			if rule.SourceSHA256 == "" || len(report.Rules) != 2 {
				t.Fatalf("规则记录不完整: %+v", report.Rules)
			}
			// 正文截断影响使用同一响应的全部规则，其余场景只影响出错的规则。
			if ok, _ := findRule(report, "ok"); !ok.Matched || ok.Completed == (tc.name == "budget") {
				t.Fatalf("正常规则的记录: %+v", ok)
			}
			for _, failure := range rule.Failures {
				if len(failure.Message) > 256 || strings.Contains(failure.Message, "aaaaaaaaaaaaaaaa") {
					t.Fatalf("失败说明无界或包含正文: %q", failure.Message)
				}
			}
			if tc.name == "records" && (!report.Truncated || len(rule.Failures) != 17) {
				t.Fatalf("超出记录上限应截断: truncated=%v failures=%d", report.Truncated, len(rule.Failures))
			}
		})
	}
}

// 全部规则正常求值时报告完整；命中与未命中都如实记录。
func TestEvaluationReportComplete(t *testing.T) {
	server := reportServer(t)
	e := newRuleEngine(t, map[string]string{"hit": exprRule("hit", `response.status == 200`), "miss": exprRule("miss", `response.status == 404`)})
	var report sdk.EvaluationReport
	if _, err := e.ScanWith(context.Background(), server.URL, sdk.ScanEvaluationReport(&report)); err != nil {
		t.Fatal(err)
	}
	hit, _ := findRule(report, "hit")
	miss, _ := findRule(report, "miss")
	if !report.Complete || report.Truncated || !hit.Matched || miss.Matched || !hit.Completed || !miss.Completed {
		t.Fatalf("%+v", report)
	}
}

// 规则执行中 panic：只影响该规则，报告记为 panic；交换回调的 panic 同样被规则池拦住。
func TestEvaluationReportPanic(t *testing.T) {
	server := reportServer(t)
	e := newRuleEngine(t, map[string]string{"boom": subRuleRule("boom", "/boom", `response.status == 200`, ""), "ok": exprRule("ok", `response.status == 200`)})
	observer := func(ex sdk.Exchange) {
		if ex.RuleID == "boom" && !ex.Cached {
			panic("observer failure")
		}
	}
	var report sdk.EvaluationReport
	result, err := e.ScanWith(context.Background(), server.URL, sdk.ScanEvaluationReport(&report), sdk.ScanObserver(observer, sdk.ExchangeLimits{}))
	if err != nil {
		t.Fatal(err)
	}
	boom, _ := findRule(report, "boom")
	if report.Complete || !slices.Contains(failureStages(boom), sdk.StagePanic) || !reflect.DeepEqual(resultIDs(result), []string{"ok"}) {
		t.Fatalf("report=%+v matches=%v", report, resultIDs(result))
	}
}

// 扫描被取消时报告不完整，且扫描返回取消错误。
func TestEvaluationReportCanceled(t *testing.T) {
	server := reportServer(t)
	e := newRuleEngine(t, map[string]string{"slow": subRuleRule("slow", "/slow", `response.status == 200`, ""), "ok": exprRule("ok", `response.status == 200`)})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	report := sdk.EvaluationReport{Complete: true}
	_, err := e.ScanWith(ctx, server.URL, sdk.ScanEvaluationReport(&report))
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || report.Complete {
		t.Fatalf("err=%v report=%+v", err, report)
	}
}

// 入口不可达时 HTTP 规则没有执行，报告逐条记为请求失败。
func TestEvaluationReportEntryFailure(t *testing.T) {
	server := reportServer(t)
	target := server.URL
	server.Close()
	e := newRuleEngine(t, map[string]string{"ok": exprRule("ok", `response.status == 200`)})
	var report sdk.EvaluationReport
	if _, err := e.ScanWith(context.Background(), target, sdk.ScanEvaluationReport(&report)); err == nil {
		t.Fatal("入口不可达应报错")
	}
	if rule, _ := findRule(report, "ok"); report.Complete || !slices.Contains(failureStages(rule), sdk.StageRequest) {
		t.Fatalf("%+v", report)
	}
}

// 单规则调试：子规则结果、交换记录、证据与输出齐全，结论与扫描一致。
func TestDebugRule(t *testing.T) {
	var apiHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" {
			apiHits.Add(1)
			_, _ = w.Write([]byte(`{"version":"v2.4.1"}`))
			return
		}
		_, _ = w.Write([]byte("<html>Demo Console</html>"))
	}))
	defer server.Close()
	rule := "id: demo\ninfo:\n  name: demo\nrules:\n" +
		"  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b\"Demo Console\")\n" +
		"  r1:\n    request:\n      method: GET\n      path: /api\n    expression: response.body.bcontains(b\"version\")\n    output:\n      product_version: '\"v(?P<v>[0-9.]+)\".bsubmatch(response.body)[\"v\"]'\n" +
		"  r2:\n    request:\n      method: GET\n      path: /\n    expression: response.status == 500\n" +
		"expression: r0() && r1() && !r2()\n"
	e := newRuleEngine(t, map[string]string{"demo": rule, "other": exprRule("other", `true`)}, sdk.WithMatchDetails(false))
	scan, err := e.Scan(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	debug, err := e.DebugRule(context.Background(), server.URL, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if debug.Match == nil || debug.Match.Info.ID != "demo" || debug.Match.ProductVersion != "2.4.1" || !slices.Contains(resultIDs(scan), "demo") {
		t.Fatalf("调试结论与扫描不一致: %+v scan=%v", debug.Match, resultIDs(scan))
	}
	if !debug.Evaluation.Completed || !debug.Evaluation.Matched || len(debug.SubRules) != 3 {
		t.Fatalf("%+v", debug)
	}
	want := map[string]bool{"r0": true, "r1": true, "r2": false}
	for _, sub := range debug.SubRules {
		if sub.Result == nil || *sub.Result != want[sub.Key] || len(sub.Exchanges) != 1 || len(sub.Evidence) == 0 {
			t.Fatalf("%s: result=%v exchanges=%d evidence=%d", sub.Key, sub.Result, len(sub.Exchanges), len(sub.Evidence))
		}
		exchange := sub.Exchanges[0]
		if exchange.RuleID != "demo" || exchange.SubRule != sub.Key || exchange.Cached != (sub.Key != "r1") {
			t.Fatalf("%s 的交换记录: %+v", sub.Key, exchange)
		}
	}
	if debug.SubRules[1].Outputs["product_version"] != "2.4.1" {
		t.Fatalf("输出: %+v", debug.SubRules[1].Outputs)
	}
	if _, err := e.DebugRule(context.Background(), server.URL, "missing"); err == nil {
		t.Fatal("不存在的规则应报错")
	}
}
