package sdk

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sampleResult() *TargetResult {
	return &TargetResult{
		URL:        "https://example.com",
		StatusCode: 200,
		Title:      "Example",
		Server:     &ServerInfo{ServerType: "nginx"},
		ICP:        "京ICP备12345号",
		Matches: []FingerMatch{
			{
				Info:   FingerInfo{ID: "fp-1", Name: "Nginx"},
				Result: true,
			},
		},
	}
}

func TestNopWriter_NoopAndIdempotentClose(t *testing.T) {
	w := NopWriter()
	if err := w.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Write returned err: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close returned err: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got %v", err)
	}
}

func TestFileWriter_JSONWritesLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	w, err := NewFileWriter(path, FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}

	if err := w.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatalf("expected trailing newline, got %q", raw)
	}

	var got TargetResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &got); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if got.URL != "https://example.com" || got.StatusCode != 200 {
		t.Fatalf("unexpected decoded result: %+v", got)
	}
}

func TestFileWriter_CSVWritesHeaderAndRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")

	w, err := NewFileWriter(path, FormatCSV)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	if err := w.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "URL") || !strings.Contains(text, "https://example.com") {
		t.Fatalf("CSV missing expected content: %q", text)
	}
}

func TestFileWriter_TXTContainsCoreFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	w, err := NewFileWriter(path, FormatTXT)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	if err := w.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(raw)
	for _, want := range []string{"https://example.com", "Example", "Nginx"} {
		if !strings.Contains(text, want) {
			t.Fatalf("txt missing %q in output: %s", want, text)
		}
	}
}

func TestFileWriter_EmptyPathReturnsNop(t *testing.T) {
	w, err := NewFileWriter("", FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter empty path: %v", err)
	}
	if _, ok := w.(nopWriter); !ok {
		t.Fatalf("expected nopWriter, got %T", w)
	}
}

func TestFileWriter_ClosingIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent.json")
	w, err := NewFileWriter(path, FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got %v", err)
	}
}

func TestMultiWriter_FansOutAndCollectsErrors(t *testing.T) {
	dir := t.TempDir()
	a, err := NewFileWriter(filepath.Join(dir, "a.json"), FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter a: %v", err)
	}
	b, err := NewFileWriter(filepath.Join(dir, "b.json"), FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter b: %v", err)
	}

	counted := &countingWriter{}
	mw := NewMultiWriter(a, b, counted)
	if err := mw.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("MultiWriter.Write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("MultiWriter.Close: %v", err)
	}

	if got := counted.writes.Load(); got != 1 {
		t.Fatalf("expected counted writer to receive 1 write, got %d", got)
	}
}

func TestFileWriter_QueueFallsBackToSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fallback.json")

	wIface, err := NewFileWriter(path, FormatJSON)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	defer wIface.Close()

	fw, ok := wIface.(*fileWriter)
	if !ok {
		t.Fatalf("expected *fileWriter, got %T", wIface)
	}

	for i := 0; i < fileQueueSize; i++ {
		select {
		case fw.queue <- sampleResult():
		default:
			t.Fatalf("failed to pre-fill queue at iter %d", i)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = fw.Write(context.Background(), sampleResult())
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("queue-full write should fall back to sync path without blocking")
	}
}

type countingWriter struct {
	writes atomic.Int64
}

func (c *countingWriter) Write(_ context.Context, r *TargetResult) error {
	if r != nil {
		c.writes.Add(1)
	}
	return nil
}

func (c *countingWriter) Close() error { return nil }

func TestSockWriter_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sock")

	w, err := NewSockWriter(path)
	if err != nil {
		t.Fatalf("NewSockWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer conn.Close()

	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		sw := w.(*sockWriter)
		sw.mu.Lock()
		n := len(sw.conns)
		sw.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := w.Write(context.Background(), sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read from socket: %v", err)
	}
	var got TargetResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &got); err != nil {
		t.Fatalf("invalid JSON broadcast: %v line=%q", err, line)
	}
	if got.URL != "https://example.com" {
		t.Fatalf("unexpected URL via socket: %s", got.URL)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close must be idempotent, got %v", err)
	}
}

func TestSockWriter_EmptyPathReturnsNop(t *testing.T) {
	w, err := NewSockWriter("")
	if err != nil {
		t.Fatalf("NewSockWriter empty path: %v", err)
	}
	if _, ok := w.(nopWriter); !ok {
		t.Fatalf("expected nopWriter for empty sock path, got %T", w)
	}
}
