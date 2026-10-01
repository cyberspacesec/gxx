package cel

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"github.com/cyberspacesec/gxx/utils/proto"
)

func indexedLibrary(t *testing.T) (*PreparedLibrary, []string) {
	t.Helper()
	needles := []string{"needle", "MiXeD", "中文", "İKΣς", "\xff", "\x00\xfe", "<Title>test</Title>"}
	for i := 0; i < 32; i++ {
		needles = append(needles, fmt.Sprintf("word-%02d", i))
	}
	var expressions []string
	for _, method := range []string{"bcontains", "ibcontains"} {
		for _, needle := range needles {
			expressions = append(expressions, fmt.Sprintf("response.body.%s(b%q)", method, needle))
		}
	}
	p, err := PrepareLibrary(nil, expressions)
	if err != nil {
		t.Fatal(err)
	}
	return p, needles
}

func TestGramFilterNeverRejectsExistingSubstrings(t *testing.T) {
	rng := rand.New(rand.NewSource(93))
	for i := 0; i < 100; i++ {
		data := make([]byte, 8192)
		rng.Read(data)
		filter := newGramFilter(data)
		if filter == nil {
			t.Fatal("稀疏位图被禁用")
		}
		for j := 0; j < 100; j++ {
			start := rng.Intn(len(data) - 100)
			needle := data[start : start+rng.Intn(96)+4]
			if !filter.mayContain(needle, false) {
				t.Fatalf("真实子串被过滤: %x", needle)
			}
		}
	}
	random := make([]byte, 1<<20)
	rng.Read(random)
	if newGramFilter(random) != nil {
		t.Fatal("饱和位图未回退")
	}
}

func TestIndexedContainsPreservesByteAndUnicodeSemantics(t *testing.T) {
	p, needles := indexedLibrary(t)
	ctx := WithResponseCache(context.Background())
	for _, size := range []int{0, 32, 4096, 32768} {
		for _, suffix := range []string{"none", "NEEDLE word-07中文iKσς", strings.Join(needles, "|")} {
			body := []byte(strings.Repeat("a ", size) + suffix)
			lib := p.NewEvaluation()
			for _, method := range []string{"bcontains", "ibcontains"} {
				for _, needle := range append(append([]string(nil), needles...), "", "unindexed-needle") {
					expression := fmt.Sprintf("response.body.%s(b%q)", method, needle)
					got, err := lib.EvaluateContext(ctx, expression, map[string]any{"response": &proto.Response{Body: body}})
					want := bytes.Contains(body, []byte(needle))
					if method == "ibcontains" {
						want = bytes.Contains(bytes.ToLower(body), bytes.ToLower([]byte(needle)))
					}
					if err != nil || got.Value() != want {
						t.Fatalf("%s size=%d got=%v want=%t err=%v", expression, size, got, want, err)
					}
				}
			}
		}
	}
	cache := ctx.Value(responseCacheKey{}).(*responseCache)
	indexed := 0
	for _, match := range cache.matches {
		if match.filter != nil {
			indexed++
		}
	}
	if indexed == 0 {
		t.Fatal("未执行批量匹配路径")
	}
}

func TestIndexedContainsConcurrentAndBudgetFallback(t *testing.T) {
	_, needles := indexedLibrary(t)
	ctx := WithResponseCache(context.Background())
	body := []byte(strings.Repeat("x", 8192) + strings.Join(needles, "|"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, needle := range needles {
				if !containsResponse(ctx, body, []byte(needle), true) {
					t.Errorf("并发匹配遗漏: %q", needle)
				}
			}
		}()
	}
	wg.Wait()
	cache := ctx.Value(responseCacheKey{}).(*responseCache)
	cache.bytes = responseCacheBudget
	uncached := append([]byte(nil), body...)
	if !containsResponse(ctx, uncached, []byte("needle"), true) || containsResponse(ctx, uncached, []byte("missing"), false) {
		t.Fatal("预算不足时匹配行为发生变化")
	}
	if cache.bytes != responseCacheBudget {
		t.Fatal("缓存超过预算")
	}
}
