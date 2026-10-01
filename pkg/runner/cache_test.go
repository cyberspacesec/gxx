package runner

import (
	"bytes"
	"context"
	"github.com/cyberspacesec/gxx/utils/proto"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheRejectsEntryOverByteBudget(t *testing.T) {
	c := NewCacheManagerWithBudget(10, time.Minute, 1024)
	defer c.Close()
	c.Set("host", "key", &CacheRequest{Request: &proto.Request{}, Response: &proto.Response{Body: make([]byte, 2048)}})
	if _, ok := c.Get("key"); ok {
		t.Fatal("oversized entry retained")
	}
}

func TestPublicCacheWriteCopiesCallerData(t *testing.T) {
	c := NewCacheManagerWithBudget(10, time.Minute, 4096)
	defer c.Close()
	req := &proto.Request{Method: "GET", Headers: map[string]string{"key": "original"}}
	resp := &proto.Response{Body: []byte("original"), Headers: map[string]string{"key": "original"}}
	c.UpdateTargetCache(map[string]any{"request": req, "response": resp}, "http://example.com/", true)
	req.Headers["key"] = "changed"
	resp.Headers["key"] = "changed"
	clear(resp.Body)
	got, ok := c.cache.GetIfPresent(c.requestKey("http://example.com", "GET", true))
	if !ok || string(got.Response.Body) != "original" || got.Response.Headers["key"] != "original" || got.Request.Headers["key"] != "original" {
		t.Fatal("公共缓存写入保留了调用方可变数据")
	}
}

func TestOwnedCachePreservesCompleteResponse(t *testing.T) {
	c := NewCacheManagerWithBudget(10, time.Minute, 8<<20).newScope()
	defer c.Close()
	body := bytes.Repeat([]byte("x"), (2<<20)+17)
	copy(body[len(body)-8:], "tailmark")
	c.updateOwnedTargetCache(map[string]any{"request": &proto.Request{Method: "GET"}, "response": &proto.Response{Body: body}}, "http://example.com/", true)
	got, ok := c.cache.GetIfPresent(c.requestKey("http://example.com", "GET", true))
	if !ok || !bytes.Equal(got.Response.Body, body) || !bytes.HasSuffix(got.Response.Body, []byte("tailmark")) {
		t.Fatal("缓存裁剪了响应尾部")
	}
	if &got.Response.Body[0] != &body[0] {
		t.Fatal("独占消息被额外复制")
	}

}

func TestRuleBatchContinuesAfterPanicAndCompletesStats(t *testing.T) {
	var called atomic.Int64
	p, err := NewRulePool(1, func(task *RuleTask) {
		called.Add(1)
		if task.Target == "panic" {
			panic("规则异常")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release(context.Background())
	var wg sync.WaitGroup
	batch := acquireRuleBatch()
	batch.count = ruleBatchSize
	wg.Add(ruleBatchSize)
	for i := range batch.count {
		task := acquireRuleTask()
		task.WaitGroup = &wg
		if i == 2 {
			task.Target = "panic"
		}
		batch.tasks[i] = task
	}
	if err := p.submitBatch(batch); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("异常导致批内任务未完成")
	}
	stats := p.Stats()
	if called.Load() != ruleBatchSize || stats.TotalTasks != ruleBatchSize || stats.CompletedTasks != ruleBatchSize-1 || stats.FailedTasks != 1 {
		t.Fatalf("批内规则或完成统计缺失: %+v called=%d", stats, called.Load())
	}
}

func TestCacheScopesShareBudgetAndIsolateValues(t *testing.T) {
	c := NewCacheManagerWithBudget(10, time.Minute, 4096)
	defer c.Close()
	a, b := c.newScope(), c.newScope()
	if a.cache != b.cache || a.scope == b.scope {
		t.Fatal("作用域未共享容量或标识重复")
	}
	a.Set("host", "same-key", &CacheRequest{Request: &proto.Request{}, Response: &proto.Response{Body: []byte("a")}})
	b.Set("host", "same-key", &CacheRequest{Request: &proto.Request{}, Response: &proto.Response{Body: []byte("b")}})
	for _, scoped := range []*CacheManager{a, b} {
		got, ok := scoped.Get("same-key")
		if !ok || string(got.Response.Body) != map[*CacheManager]string{a: "a", b: "b"}[scoped] {
			t.Fatal("响应跨作用域串用")
		}
	}
	a.clearScope()
	if _, ok := a.Get("same-key"); ok {
		t.Fatal("作用域未清理")
	}
	if _, ok := b.Get("same-key"); !ok {
		t.Fatal("清理影响其他作用域")
	}
}
func TestRulePoolRespectsSmallCapacity(t *testing.T) {
	var active, peak atomic.Int64
	var wg sync.WaitGroup
	p, err := NewRulePool(1, func(*RuleTask) {
		defer wg.Done()
		n := active.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		if err := p.Submit(&RuleTask{}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	p.Release(context.Background())
	if peak.Load() != 1 {
		t.Fatalf("peak=%d", peak.Load())
	}
}
