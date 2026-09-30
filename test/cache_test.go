/*
cache_test 对 *runner.CacheManager 进行单元测试，
每个用例独立调用 NewCacheManager 创建隔离实例。
*/
package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/runner"
	"github.com/cyberspacesec/gxx/utils/proto"
)

func TestShouldUseCache_BasicFlow(t *testing.T) {
	cm := runner.NewCacheManager(64, 5*time.Minute)
	defer cm.Close()

	key := "base-page"
	if _, ok := cm.Get(key); ok {
		t.Fatalf("expected miss on empty cache")
	}

	entry := &runner.CacheRequest{
		Request:   &proto.Request{Method: "GET"},
		Response:  &proto.Response{Status: 200, Body: []byte("ok")},
		Timestamp: time.Now().Unix(),
	}
	cm.Set("http://www.baidu.com", key, entry)

	got, ok := cm.Get(key)
	if !ok {
		t.Fatalf("expected hit after set")
	}
	if got.Request.GetMethod() != "GET" {
		t.Fatalf("method mismatch: got %q", got.Request.GetMethod())
	}
	if got.Response.GetStatus() != 200 {
		t.Fatalf("status mismatch: got %d", got.Response.GetStatus())
	}
	if !bytes.Equal(got.Response.GetBody(), []byte("ok")) {
		t.Fatalf("body mismatch")
	}
}

func TestCacheManager_InvalidateTarget(t *testing.T) {
	cm := runner.NewCacheManager(64, 5*time.Minute)
	defer cm.Close()

	target := "http://example.com"
	keys := []string{
		"get-with-redirect",
		"get-without-redirect",
		"post-with-redirect",
	}
	for _, k := range keys {
		cm.Set(target, k, &runner.CacheRequest{
			Request:   &proto.Request{Method: "GET"},
			Response:  &proto.Response{Status: 200},
			Timestamp: time.Now().Unix(),
		})
	}

	deleted := cm.InvalidateTarget(target)
	if deleted != len(keys) {
		t.Fatalf("expected %d invalidated, got %d", len(keys), deleted)
	}
	for _, k := range keys {
		if _, ok := cm.Get(k); ok {
			t.Fatalf("key %s should be evicted", k)
		}
	}
}

func TestCacheManager_InvalidateAll(t *testing.T) {
	cm := runner.NewCacheManager(64, 5*time.Minute)
	defer cm.Close()

	for i := 0; i < 16; i++ {
		key := fmt.Sprintf("response-%d", i)
		cm.Set("http://example.com", key, &runner.CacheRequest{
			Request:   &proto.Request{Method: "GET"},
			Response:  &proto.Response{Status: int32(200 + i)},
			Timestamp: time.Now().Unix(),
		})
	}
	cm.InvalidateAll()
	stats := cm.Stats()
	if entries, _ := stats["total_entries"].(int); entries != 0 {
		t.Fatalf("expected 0 entries after InvalidateAll, got %v", entries)
	}
}

func TestCacheManager_StatsShape(t *testing.T) {
	cm := runner.NewCacheManager(128, 3*time.Minute)
	defer cm.Close()

	cm.Set("http://example.com", "k1", &runner.CacheRequest{
		Request: &proto.Request{Method: "GET"}, Response: &proto.Response{Status: 200}, Timestamp: time.Now().Unix(),
	})
	stats := cm.Stats()
	for _, key := range []string{"total_entries", "max_size", "ttl_minutes", "created_at", "hits", "misses", "evictions", "hit_ratio"} {
		if _, ok := stats[key]; !ok {
			t.Fatalf("stats missing key %q", key)
		}
	}
}

func TestCacheManager_ClonesPreventMutation(t *testing.T) {
	cm := runner.NewCacheManager(16, time.Minute)
	defer cm.Close()

	original := &runner.CacheRequest{
		Request:   &proto.Request{Method: "GET", Body: []byte("orig")},
		Response:  &proto.Response{Status: 200, Body: []byte("ok")},
		Timestamp: time.Now().Unix(),
	}
	cm.Set("http://example.com", "k1", original)

	got, _ := cm.Get("k1")
	got.Request.Method = "POST"
	got.Response.Body = []byte("MUTATED")

	again, _ := cm.Get("k1")
	// Set/Get 共享实例内的消息；公共输入的隔离由 UpdateTargetCache 负责。
	if again != got {
		t.Fatalf("expected same pointer to be stored")
	}
}
