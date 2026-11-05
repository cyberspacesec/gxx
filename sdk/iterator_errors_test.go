package sdk_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// S3：ScanIterator 聚合的错误条数必须封顶，大批量失败目标时不无界增长。
func TestScanIteratorCapsAccumulatedErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String() + "/"
	_ = ln.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("id: t\ninfo:\n  name: t\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: 'true'\nexpression: r0()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := sdk.NewEngine(context.Background(), sdk.WithFingerOptions(sdk.FingerOptions{PocFile: dir}), sdk.WithTimeout(time.Second), sdk.WithURLConcurrency(20))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	const total = 500
	targets := func(yield func(string) bool) {
		for i := 0; i < total; i++ {
			if !yield(dead) {
				return
			}
		}
	}
	err = e.ScanIterator(context.Background(), targets, func(*sdk.TargetResult) bool { return true })
	if err == nil {
		t.Fatal("全部目标失败应返回错误")
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) {
		t.Fatalf("错误应可展开为多条: %v", err)
	}
	count := len(joined.Unwrap())
	// 上限 100 条明细 + 最多 1 条截断汇总。
	if count > 102 {
		t.Fatalf("错误条数未封顶: %d（期望 ≤ 102）", count)
	}
	if count < 2 {
		t.Fatalf("应聚合多条错误: %d", count)
	}
}
