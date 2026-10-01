package sdk_test

import (
	"context"
	"errors"
	"github.com/cyberspacesec/gxx/v2/sdk"
	"sync/atomic"
	"testing"
)

func TestScanIteratorBackpressureAndEarlyStop(t *testing.T) {
	e, target := fullRuleFixture(t, 0)
	var generated atomic.Int32
	iterator := func(yield func(string) bool) {
		for i := 0; i < 1000000; i++ {
			generated.Add(1)
			if !yield(target) {
				return
			}
		}
	}
	callbacks := 0
	if err := e.ScanIterator(context.Background(), iterator, func(*sdk.TargetResult) bool { callbacks++; return false }); err != nil {
		t.Fatal(err)
	}
	if callbacks != 1 || generated.Load() > 6 {
		t.Fatalf("未保持背压: callbacks=%d generated=%d", callbacks, generated.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.ScanIterator(ctx, iterator, func(*sdk.TargetResult) bool { return true }); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消未传播: %v", err)
	}
	if err := e.ScanIterator(context.Background(), nil, func(*sdk.TargetResult) bool { return true }); !errors.Is(err, sdk.ErrInvalidOption) {
		t.Fatalf("未拒绝 nil 迭代器: %v", err)
	}
}
