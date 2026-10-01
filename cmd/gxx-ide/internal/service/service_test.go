package service

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLibraryRestrictsPathsAndPreservesFailedSaves(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	s := NewLibraryService()
	if _, e := s.List(dir, false); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "a.yaml")
	if e := s.Save(&model.SaveYAMLInput{Path: path, Content: "id: a"}); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(&model.SaveYAMLInput{Path: path, Content: "rules: ["}); e == nil {
		t.Fatal("invalid YAML saved")
	}
	r, e := s.Load(path)
	if e != nil || r.Content != "id: a" {
		t.Fatalf("%+v %v", r, e)
	}
	external := filepath.Join(outside, "b.yaml")
	os.WriteFile(external, []byte("id: b"), 0600)
	if _, e := s.Load(external); e == nil {
		t.Fatal("external path allowed")
	}
	link := filepath.Join(dir, "escape")
	if e := os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	escaped := filepath.Join(link, "b.yaml")
	if _, e := s.Load(escaped); e == nil {
		t.Fatal("symlink escaped root")
	}
	if e := s.Save(&model.SaveYAMLInput{Path: escaped, Content: "id: replaced"}); e == nil {
		t.Fatal("symlink save escaped root")
	}
	data, _ := os.ReadFile(external)
	if string(data) != "id: b" {
		t.Fatal("external content changed")
	}
	if e := s.Save(&model.SaveYAMLInput{Path: filepath.Join(dir, "plain.conf"), Content: "id: a"}); e == nil {
		t.Fatal("non YAML allowed")
	}
}
func TestRawRespectsCancellationAndProxy(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "ok") }))
	defer srv.Close()
	in := &model.SendRequestInput{Mode: model.RequestModeRaw, Raw: "GET / HTTP/1.1\r\nHost: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n\r\n", Proxy: "http://127.0.0.1:1", TimeoutSeconds: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := NewRequestService().Send(ctx, in); e == nil {
		t.Fatal("cancellation ignored")
	}
	if _, e := NewRequestService().Send(context.Background(), in); e == nil {
		t.Fatal("proxy ignored")
	}
	if hits.Load() != 0 {
		t.Fatal("sent direct request")
	}
}
func TestCELDebugCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewFingerService().EvaluateCELContext(ctx, &model.EvaluateCELInput{Expression: "sleep(1000)"})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("%v %v", time.Since(start), err)
	}
}

func TestFingerprintOutputsRequireSuccessfulRuleAndExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "version/1.2.3")
	}))
	defer server.Close()
	for _, extract := range []string{`"version/(?<version>[0-9.]+)".bsubmatch(response.body)["version"]`, `"[".bsubmatch(response.body)["version"]`} {
		yaml := "id: output\ninfo:\n  name: 输出测试\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: false\n    output:\n      unmatch_output: '\"incorrect\"'\n  r1:\n    request:\n      method: GET\n      path: /\n    expression: true\n    output:\n      product_version: '" + extract + "'\nexpression: r1()\n"
		result, err := NewFingerService().Run(context.Background(), &model.RunFingerprintInput{YAML: yaml, Target: server.URL, TimeoutSeconds: 2})
		if err != nil || !result.FinalResult {
			t.Fatalf("%+v %v", result, err)
		}
		found := false
		for _, variable := range result.Variables {
			if variable.Key == "unmatch_output" {
				t.Fatal("未命中子规则输出出现在调试变量中")
			}
			if variable.Key == "product_version" {
				found = true
				if !strings.Contains(variable.Value, "1.2.3") {
					t.Fatalf("提取表达式原文成为版本: %+v", variable)
				}
			}
		}
		if found == strings.Contains(extract, `"["`) {
			t.Fatalf("提取失败仍返回版本或成功版本缺失: %+v", result.Variables)
		}
	}
}
