package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
)

// 提交方数量超过规则池容量时，任务只能排队等待，不能被拒绝。
func TestRulePoolQueuesInsteadOfRejectingWhenSubmittersExceedCapacity(t *testing.T) {
	const submitters = 32
	var handled atomic.Int64
	p, err := NewRulePool(1, func(*RuleTask) {
		time.Sleep(5 * time.Millisecond)
		handled.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release(context.Background())

	var wg sync.WaitGroup
	var rejected atomic.Int64
	start := make(chan struct{})
	for range submitters {
		// 与生产路径一致：任务来自 acquireRuleTask（pooled=true），执行完成后由池调用 wg.Done()。
		task := acquireRuleTask()
		wg.Add(1)
		task.WaitGroup = &wg
		go func() {
			<-start
			if err := p.Submit(task); err != nil {
				// 被拒绝的任务不会进入池，需要由提交方自己收尾。
				rejected.Add(1)
				releaseRuleTask(task)
				wg.Done()
			}
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("任务没有全部完成")
	}
	if rejected.Load() != 0 || handled.Load() != submitters {
		t.Fatalf("提交=%d 被拒绝=%d 已处理=%d", submitters, rejected.Load(), handled.Load())
	}
}

// 端到端：URL 并发远高于规则并发时，每个目标仍必须评估完全部指纹，结果不能因为排队而缺失。
func TestScanTargetEvaluatesEveryFingerprintWhenURLConcurrencyExceedsRuleConcurrency(t *testing.T) {
	const fingers, targets = 5, 16
	dir := t.TempDir()
	for i := range fingers {
		rule := fmt.Sprintf("id: slow-%[1]d\ninfo:\n  name: slow-%[1]d\nrules:\n  r0:\n    request:\n      method: GET\n      path: /p%[1]d\n    expression: response.status == 200 && response.body.bcontains(b'ok-%[1]d')\nexpression: r0()\n", i)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("slow-%d.yaml", i)), []byte(rule), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/p%d", &n); err == nil {
			time.Sleep(20 * time.Millisecond) // 让规则任务占住 worker，迫使提交方排队
			fmt.Fprintf(w, "ok-%d", n)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><title>t</title></html>")
	}))
	defer server.Close()

	r, err := NewRunner(ScanConfig{Logger: logger.Discard(), URLWorkerCount: targets, FingerWorkerCount: 1, Timeout: 5 * time.Second}, types.YamlFingerType{PocFile: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var wg sync.WaitGroup
	matches := make([]int, targets)
	errs := make([]error, targets)
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := r.ScanTarget(context.Background(), server.URL)
			if err != nil {
				errs[i] = err
				return
			}
			matches[i] = len(res.Matches)
		}()
	}
	wg.Wait()
	for i := range targets {
		if errs[i] != nil || matches[i] != fingers {
			t.Fatalf("目标 %d: 命中=%d 期望=%d err=%v", i, matches[i], fingers, errs[i])
		}
	}
	if stats := r.PoolStats(); stats.TotalTasks != int64(fingers*targets) || stats.CompletedTasks != int64(fingers*targets) {
		t.Fatalf("规则任务被丢弃: %+v 期望=%d", stats, fingers*targets)
	}
}
