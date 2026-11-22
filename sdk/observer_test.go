package sdk_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cyberspacesec/gxx/sdk"
)

type exchangeLog struct {
	mu   sync.Mutex
	list []sdk.Exchange
}

func (l *exchangeLog) observe(ex sdk.Exchange) {
	l.mu.Lock()
	l.list = append(l.list, ex)
	l.mu.Unlock()
}

func (l *exchangeLog) find(match func(sdk.Exchange) bool) []sdk.Exchange {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []sdk.Exchange
	for _, ex := range l.list {
		if match(ex) {
			out = append(out, ex)
		}
	}
	return out
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// 大响应、分块与压缩响应：ResponseBody 是前 MaxBody 字节，BodyBytes 与 BodySHA256
// 覆盖引擎实际读取的完整正文；正文超过引擎读取上限时只覆盖读到的部分并标记截断。
func TestObserverBodyTruncationAndDigest(t *testing.T) {
	large := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write(large)
	_ = gz.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			_, _ = w.Write(large)
		case "/chunked":
			flusher := w.(http.Flusher)
			for i := 0; i < len(large); i += 4096 {
				_, _ = w.Write(large[i : i+4096])
				flusher.Flush()
			}
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressed.Bytes())
		default:
			_, _ = w.Write([]byte("<html>index</html>"))
		}
	}))
	defer server.Close()
	rules := map[string]string{}
	for _, path := range []string{"/large", "/chunked", "/gzip"} {
		id := "body" + strings.ReplaceAll(path, "/", "-")
		rules[id] = subRuleRule(id, path, `response.status == 200`, "")
	}
	for _, limit := range []int64{0, 10000} {
		var opts []sdk.Option
		if limit > 0 {
			opts = append(opts, sdk.WithBodyLimit(limit))
		}
		e := newRuleEngine(t, rules, opts...)
		var log exchangeLog
		if _, err := e.ScanWith(context.Background(), server.URL, sdk.ScanObserver(log.observe, sdk.ExchangeLimits{MaxBody: 1024})); err != nil {
			t.Fatal(err)
		}
		read := large
		if limit > 0 {
			read = large[:limit]
		}
		for _, path := range []string{"/large", "/chunked", "/gzip"} {
			found := log.find(func(ex sdk.Exchange) bool { return strings.HasSuffix(ex.URL, path) && !ex.Cached })
			if len(found) != 1 {
				t.Fatalf("%s: 记录数 %d", path, len(found))
			}
			ex := found[0]
			if ex.BodyBytes != int64(len(read)) || ex.BodySHA256 != digest(read) || !bytes.Equal(ex.ResponseBody, read[:1024]) || !ex.BodyTruncated || ex.StatusCode != 200 || ex.Kind != sdk.RequestHTTP {
				t.Fatalf("limit=%d %s: bytes=%d sha=%s body=%d truncated=%v", limit, path, ex.BodyBytes, ex.BodySHA256, len(ex.ResponseBody), ex.BodyTruncated)
			}
		}
		index := log.find(func(ex sdk.Exchange) bool {
			return ex.RuleID == "" && !ex.Cached && strings.HasSuffix(ex.URL, server.URL[7:])
		})
		if len(index) != 1 || index[0].BodyTruncated || string(index[0].ResponseBody) != "<html>index</html>" || len(index[0].ResponseHeaderOrder) == 0 {
			t.Fatalf("入口记录: %+v", index)
		}
	}
}

// 序号按回调顺序单调递增；规则复用入口响应时回调 Cached 记录，标注所属规则。
func TestObserverSequenceAndCached(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>page</html>")) }))
	defer server.Close()
	e := newRuleEngine(t, map[string]string{"a": exprRule("a", `response.status == 200`), "b": exprRule("b", `response.body.bcontains(b"page")`)})
	var log exchangeLog
	if _, err := e.ScanWith(context.Background(), server.URL, sdk.ScanObserver(log.observe, sdk.ExchangeLimits{})); err != nil {
		t.Fatal(err)
	}
	for i, ex := range log.list {
		if ex.Sequence != i+1 {
			t.Fatalf("第 %d 条的序号为 %d", i+1, ex.Sequence)
		}
	}
	network := log.find(func(ex sdk.Exchange) bool { return !ex.Cached && ex.Kind == sdk.RequestHTTP })
	cached := log.find(func(ex sdk.Exchange) bool { return ex.Cached })
	if len(network) != 1 || len(cached) != 2 {
		t.Fatalf("network=%d cached=%d", len(network), len(cached))
	}
	for _, ex := range cached {
		if (ex.RuleID != "a" && ex.RuleID != "b") || ex.SubRule != "r0" || ex.BodySHA256 != network[0].BodySHA256 || ex.StatusCode != 200 {
			t.Fatalf("缓存记录: %+v", ex)
		}
	}
	// 记录上限之外不再回调。
	var limited exchangeLog
	if _, err := e.ScanWith(context.Background(), server.URL, sdk.ScanObserver(limited.observe, sdk.ExchangeLimits{MaxExchanges: 2})); err != nil {
		t.Fatal(err)
	}
	if len(limited.list) != 2 {
		t.Fatalf("上限 2，实际 %d", len(limited.list))
	}
}

// 并发扫描各自回调自己的交换，互不串扰。
func TestObserverConcurrentScansAreIsolated(t *testing.T) {
	servers := make([]*httptest.Server, 4)
	for i := range servers {
		body := []byte("<html>site" + string(rune('A'+i)) + "</html>")
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
		defer servers[i].Close()
	}
	e := newRuleEngine(t, map[string]string{"a": exprRule("a", `response.status == 200`)})
	logs := make([]exchangeLog, len(servers))
	var wg sync.WaitGroup
	for round := 0; round < 5; round++ {
		for i := range servers {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := e.ScanWith(context.Background(), servers[i].URL, sdk.ScanObserver(logs[i].observe, sdk.ExchangeLimits{})); err != nil {
					t.Error(err)
				}
			}(i)
		}
	}
	wg.Wait()
	for i := range servers {
		if len(logs[i].list) == 0 {
			t.Fatalf("扫描 %d 没有记录", i)
		}
		for _, ex := range logs[i].list {
			if !strings.HasPrefix(ex.URL, servers[i].URL) {
				t.Fatalf("扫描 %d 收到了其他扫描的记录: %s", i, ex.URL)
			}
		}
	}
}
