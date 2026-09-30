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
