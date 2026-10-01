package cel_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	gcel "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/utils/proto"
)

func TestEvidenceUsesExecutedLogicalBranches(t *testing.T) {
	for _, test := range []struct {
		expression string
		body       []byte
		wanted     string
		field      string
		matched    bool
	}{
		{`response.body.bcontains(b"missing") || response.body.bcontains(b"marker")`, []byte("prefix marker suffix"), "marker", "response.body", true},
		{`response.status == 200 && response.body.bcontains(b"marker")`, []byte("prefix marker suffix"), "marker", "response.body", true},
		{`!response.body.bcontains(b"missing")`, []byte("marker"), "", "response.body", false},
		{`response.body.ibcontains(b"ik")`, []byte("前缀İKΣς后缀"), "İK", "response.body", true},
		{`"(?<m>marker)".bmatches(response.body)`, []byte("前缀marker后缀"), "marker", "response.body", true},
		{`string(response.body).matches("[[:alpha:]]+")`, []byte("前缀marker后缀"), "marker", "response.body", true},
		{`string(response.body).matches("\\p{Han}+")`, []byte("前缀marker后缀"), "前缀", "response.body", true},
		{`response.headers["server"] == "Apache/2.4.62"`, []byte(""), "Apache/2.4.62", "response.headers.server", true},
		{`response.body.bcontains(b"marker")`, []byte{0xff, 'm', 'a', 'r', 'k', 'e', 'r', 0}, "marker", "response.body", true},
	} {
		t.Run(test.expression, func(t *testing.T) {
			lib := gcel.NewCustomLib()
			lib.SetEvidenceEnabled(true)
			lib.SetContext(gcel.WithResponseCache(context.Background()))
			variables := map[string]any{"response": &proto.Response{Body: test.body, Status: 200, Headers: map[string]string{"server": "Apache/2.4.62"}}}
			out, err := lib.Evaluate(test.expression, variables)
			if err != nil || out.Value() != true {
				t.Fatalf("value=%v error=%v", out, err)
			}
			evidence, truncated := lib.Evidence(variables)
			if truncated {
				t.Fatal("简单证据被截断")
			}
			var found bool
			for _, item := range evidence {
				if item.Field != test.field {
					continue
				}
				found = true
				if item.Matched != test.matched {
					t.Fatalf("逻辑分支不一致: %+v", item)
				}
				if test.wanted == "" {
					if item.Start != -1 || item.End != -1 {
						t.Fatalf("阴性条件出现命中位置: %+v", item)
					}
					continue
				}
				data := test.body
				if test.field == "response.headers.server" {
					data = []byte("Apache/2.4.62")
				}
				if item.Start < 0 || item.End > len(data) || string(data[item.Start:item.End]) != test.wanted {
					t.Fatalf("字节位置错误: %+v, body=%q", item, data)
				}
				if strings.Contains(item.Expression, "missing") {
					t.Fatalf("OR 的失败分支被标为证据: %+v", item)
				}
				if item.Encoding == "base64" {
					snippet, err := base64.StdEncoding.DecodeString(item.Snippet)
					if err != nil || !bytes.Contains(snippet, []byte(test.wanted)) {
						t.Fatalf("二进制片段错误: %+v", item)
					}
				}
			}
			if !found {
				t.Fatalf("未回传实际执行的字段: %+v", evidence)
			}
		})
	}
}

func TestEvidenceDoesNotExecuteShortCircuitedIO(t *testing.T) {
	lib := gcel.NewCustomLib()
	lib.SetEvidenceEnabled(true)
	value, err := lib.Evaluate(`true || sleep(3600) == null`, nil)
	if err != nil || value.Value() != true {
		t.Fatalf("%v %v", value, err)
	}
	evidence, _ := lib.Evidence(nil)
	for _, item := range evidence {
		if strings.Contains(item.Expression, "sleep") {
			t.Fatalf("未执行分支出现在证据中: %+v", evidence)
		}
	}
}

func TestPreparedEvidenceStateIsIsolated(t *testing.T) {
	expression := `response.body.bcontains(b"marker")`
	plan, err := gcel.PrepareLibrary(nil, []string{expression}, true)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 20; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			body := []byte(strings.Repeat("x", index) + "marker")
			for iteration := 0; iteration < 20; iteration++ {
				lib := plan.NewEvaluation()
				lib.SetEvidenceEnabled(true)
				variables := map[string]any{"response": &proto.Response{Body: body}}
				if _, err := lib.Evaluate(expression, variables); err != nil {
					t.Error(err)
					return
				}
				evidence, _ := lib.Evidence(variables)
				if len(evidence) != 1 || evidence[0].Start != index {
					t.Errorf("证据跨实例串用: %+v", evidence)
					return
				}
				lib.Reset()
				if evidence, _ := lib.Evidence(nil); len(evidence) != 0 {
					t.Error("Reset 后仍保留证据")
				}
			}
		}(index)
	}
	group.Wait()
}

func TestEvidenceBoundsDoNotChangeMatch(t *testing.T) {
	var predicates []string
	for index := 0; index < 80; index++ {
		predicates = append(predicates, `response.body.bcontains(b"marker")`)
	}
	lib := gcel.NewCustomLib()
	lib.SetEvidenceEnabled(true)
	variables := map[string]any{"response": &proto.Response{Body: []byte("marker")}}
	value, err := lib.Evaluate(strings.Join(predicates, " && "), variables)
	if err != nil || value.Value() != true {
		t.Fatalf("证据限制改变了识别结果: %v %v", value, err)
	}
	evidence, truncated := lib.Evidence(variables)
	if !truncated || len(evidence) > 16 {
		t.Fatalf("证据没有按预算限制: count=%d truncated=%v", len(evidence), truncated)
	}
}
