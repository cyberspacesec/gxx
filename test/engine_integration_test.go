//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// TestEngine_ScanCallback_Integration 外网流式回调（go test -tags=integration，需网络可达）。
func TestEngine_ScanCallback_Integration(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background(),
		sdk.WithTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	targets := []string{"https://example.com", "https://www.baidu.com"}
	var mu sync.Mutex
	var got []string

	cb := func(r *sdk.TargetResult) bool {
		mu.Lock()
		got = append(got, r.URL)
		mu.Unlock()
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := engine.ScanCallback(ctx, targets, cb); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ScanCallback unexpected err: %v", err)
	}
}

// TestEngine_NormalizeURL_Integration 外网 URL 规范化（go test -tags=integration）。
func TestEngine_NormalizeURL_Integration(t *testing.T) {
	engine, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()
	for _, target := range []string{"https://example.com", "http://example.com"} {
		got, err := engine.NormalizeURL(ctx, target)
		if err != nil {
			t.Skipf("NormalizeURL(%q) skipped due to network: %v", target, err)
		}
		if !strings.HasPrefix(got, "http://") && !strings.HasPrefix(got, "https://") {
			t.Fatalf("expected http(s)://... got: %s", got)
		}
	}
}
