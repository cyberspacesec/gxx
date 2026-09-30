package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// TestEngine_WithOutputFile_JSON 验证 sdk.WithOutputFile 在 Engine.Scan 完成后
// 自动把结果写入 JSON Lines 文件，且 Engine.Close 能完整 flush 异步队列。
func TestEngine_WithOutputFile_JSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "gxx-writer-test/1.0")
		_, _ = w.Write([]byte("<html><head><title>writer-test</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "result.json")

	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(3*time.Second),
		sdk.WithRuleConcurrency(20),
		sdk.WithOutputFile(outPath, sdk.FormatJSON),
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if _, err := engine.Scan(context.Background(), srv.URL); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	line := strings.TrimSpace(string(raw))
	if line == "" {
		t.Fatalf("output file should not be empty: %s", outPath)
	}
	var got sdk.TargetResult
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("invalid JSON line %q: %v", line, err)
	}
	if got.URL != srv.URL {
		t.Fatalf("unexpected URL in output: got=%s want=%s", got.URL, srv.URL)
	}
	if got.Title != "writer-test" {
		t.Fatalf("unexpected title: %q", got.Title)
	}
}

// TestEngine_WithWriter_CustomCollector 通过自定义 Writer 收集 ScanCallback 完成的
// 每条目标结果，验证 Writer 与回调可同时启用。
func TestEngine_WithWriter_CustomCollector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><title>multi</title></html>"))
	}))
	defer srv.Close()

	collector := &collectingWriter{}
	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(3*time.Second),
		sdk.WithURLConcurrency(2),
		sdk.WithRuleConcurrency(20),
		sdk.WithWriter(collector),
	)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	targets := []string{srv.URL, srv.URL, srv.URL}
	var callbacks atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := engine.ScanCallback(ctx, targets, func(*sdk.TargetResult) bool {
		callbacks.Add(1)
		return true
	}); err != nil {
		t.Fatalf("ScanCallback: %v", err)
	}

	if got := collector.count.Load(); got != int64(len(targets)) {
		t.Fatalf("expected writer to see %d results, got %d", len(targets), got)
	}
	if callbacks.Load() != int32(len(targets)) {
		t.Fatalf("expected callback to fire %d times, got %d", len(targets), callbacks.Load())
	}
}

// collectingWriter 是测试用 Writer：仅原子计数，不持有任何外部资源。
type collectingWriter struct {
	count atomic.Int64
}

func (c *collectingWriter) Write(_ context.Context, r *sdk.TargetResult) error {
	if r != nil {
		c.count.Add(1)
	}
	return nil
}

func (c *collectingWriter) Close() error { return nil }
