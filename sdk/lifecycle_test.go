package sdk_test

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/sdk"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type waitingWriter struct {
	started    chan struct{}
	done       atomic.Bool
	earlyClose atomic.Bool
}

func (w *waitingWriter) Write(ctx context.Context, _ *sdk.TargetResult) error {
	close(w.started)
	<-ctx.Done()
	w.done.Store(true)
	return ctx.Err()
}
func (w *waitingWriter) Close() error {
	if !w.done.Load() {
		w.earlyClose.Store(true)
	}
	return nil
}
func TestCloseWaitsForResultDelivery(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok")
	}))
	defer s.Close()
	w := &waitingWriter{started: make(chan struct{})}
	e := engine(t, oneRule("/"), sdk.WithWriter(w), sdk.WithTimeout(15*time.Second))
	if _, err := e.GetBaseInfo(context.Background(), s.URL); err != nil {
		t.Fatal(err)
	}
	scanDone := make(chan struct{})
	go func() { defer close(scanDone); _, _ = e.Scan(context.Background(), s.URL) }()
	select {
	case <-w.started:
	case <-time.After(15 * time.Second):
		t.Fatal("writer never started")
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked")
	}
	<-scanDone
	if w.earlyClose.Load() {
		t.Fatal("writer closed before in-flight Write finished")
	}
}
