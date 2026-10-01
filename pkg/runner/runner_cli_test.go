package runner

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCLISummaryDoesNotCarryResultsAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule.yaml")
	if err := os.WriteFile(path, []byte("id: summary-test\ninfo:\n  name: 测试\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'positive')\nexpression: r0()\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := func(body string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		t.Cleanup(s.Close)
		return s
	}
	positive, negative := server("positive"), server("negative")
	r, err := NewRunner(ScanConfig{Logger: logger.Discard(), URLWorkerCount: 2, FingerWorkerCount: 4, Timeout: time.Second}, types.YamlFingerType{PocYaml: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	for _, tc := range []struct {
		targets []string
		want    scanSummary
	}{
		{[]string{positive.URL, negative.URL}, scanSummary{matched: 1, unmatched: 1}},
		{[]string{negative.URL}, scanSummary{unmatched: 1}},
	} {
		got, err := r.executeScan(context.Background(), tc.targets, &types.CmdOptions{})
		if err != nil || got != tc.want {
			t.Fatalf("got=%+v err=%v want=%+v", got, err, tc.want)
		}
	}
}
