package cel

import (
	"bytes"
	"context"
	"sync"
)

type responseCacheKey struct{}
type bodyKey struct {
	first *byte
	size  int
}
type responseCache struct {
	mu      sync.RWMutex
	lower   map[bodyKey][]byte
	runes   map[bodyKey][]rune
	bytes   int
	matches map[literalBodyKey]literalMatches
}

type literalMatches struct {
	filter   *gramFilter
	queries  uint8
	disabled bool
}

type literalBodyKey struct {
	bodyKey
	fold bool
}

const responseCacheBudget = 8 << 20

// WithResponseCache 让同一次扫描共享只读响应的归一化结果与预筛选位图。
// 输入字节在该 context 生命周期内必须保持只读。输入、归一化结果和位图
// 共用 8 MiB 估算预算，全部随扫描 context 释放，不构成进程 RSS 硬限制。
func WithResponseCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, responseCacheKey{}, &responseCache{lower: make(map[bodyKey][]byte)})
}

func containsResponse(ctx context.Context, value, needle []byte, fold bool) bool {
	if len(value) >= 4096 && len(needle) >= 4 {
		if cache, ok := ctx.Value(responseCacheKey{}).(*responseCache); ok {
			if cache.excludes(value, needle, fold) {
				return false
			}
		}
	}
	if fold {
		return bytes.Contains(lowerResponse(ctx, value), bytes.ToLower(needle))
	}
	return bytes.Contains(value, needle)
}

// excludes 只证明必要的 4 字节片段缺失，可能命中的候选仍由 bytes.Contains
// 判断。动态字面量同样适用，不为整个指纹库保留单独的字符串自动机。
func (cache *responseCache) excludes(value, needle []byte, fold bool) bool {
	key := literalBodyKey{bodyKey: bodyKey{&value[0], len(value)}, fold: fold}
	cache.mu.RLock()
	entry := cache.matches[key]
	cache.mu.RUnlock()
	if entry.disabled {
		return false
	}
	if entry.filter != nil {
		return !entry.filter.mayContain(needle, fold)
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	entry, found := cache.matches[key]
	if entry.disabled {
		return false
	}
	if entry.filter == nil {
		if !found {
			cost := cache.inputCost(key.bodyKey)
			if len(cache.matches) >= 256 || cache.bytes+cost > responseCacheBudget {
				return false
			}
			if cache.matches == nil {
				cache.matches = make(map[literalBodyKey]literalMatches)
			}
			cache.bytes += cost
		}
		// 少量规则独占的响应不值得遍历整个索引；达到复用阈值后才计算位图。
		if entry.queries < 16 {
			entry.queries++
			cache.matches[key] = entry
			return false
		}
		cost := gramFilterBytes
		if cache.bytes+cost > responseCacheBudget {
			return false
		}
		data := value
		if fold {
			data = cache.lower[key.bodyKey]
			if data == nil {
				data = bytes.ToLower(value)
				cost += len(data)
				if cache.bytes+cost > responseCacheBudget {
					return false
				}
				cache.lower[key.bodyKey] = data
			}
		}
		entry.filter = newGramFilter(data)
		entry.disabled = entry.filter == nil
		cache.matches[key] = entry
		cache.bytes += cost
	}
	return entry.filter != nil && !entry.filter.mayContain(needle, fold)
}
func lowerResponse(ctx context.Context, value []byte) []byte {
	cache, ok := ctx.Value(responseCacheKey{}).(*responseCache)
	if !ok || len(value) < 64 {
		return bytes.ToLower(value)
	}
	key := bodyKey{&value[0], len(value)}
	cache.mu.RLock()
	lower, found := cache.lower[key]
	cache.mu.RUnlock()
	if found {
		return lower
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if lower, found = cache.lower[key]; found {
		return lower
	}
	lower = bytes.ToLower(value)
	// 不同表示的键引用同一输入，输入保留成本只计算一次。
	cost := cache.inputCost(key) + len(lower)
	if cache.bytes+cost <= responseCacheBudget {
		cache.lower[key] = lower
		cache.bytes += cost
	}
	return lower
}

// 调用方持有写锁；输入指针在任一表示的键中都能保持整段数据存活。
func (cache *responseCache) inputCost(key bodyKey) int {
	if _, found := cache.lower[key]; found {
		return 0
	}
	if _, found := cache.runes[key]; found {
		return 0
	}
	if _, found := cache.matches[literalBodyKey{bodyKey: key}]; found {
		return 0
	}
	if _, found := cache.matches[literalBodyKey{bodyKey: key, fold: true}]; found {
		return 0
	}
	return key.size
}

// regexResponseRunes 让同一只读响应的正则匹配共用字符缓冲，受同一预算约束。
func regexResponseRunes(ctx context.Context, value []byte) []rune {
	cache, ok := ctx.Value(responseCacheKey{}).(*responseCache)
	if !ok || len(value) < 64 {
		return []rune(string(value))
	}
	key := bodyKey{&value[0], len(value)}
	cache.mu.RLock()
	runes, found := cache.runes[key]
	cache.mu.RUnlock()
	if found {
		return runes
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if runes, found = cache.runes[key]; found {
		return runes
	}
	runes = []rune(string(value))
	cost := cache.inputCost(key) + 4*cap(runes)
	if cache.bytes+cost <= responseCacheBudget {
		if cache.runes == nil {
			cache.runes = make(map[bodyKey][]rune)
		}
		cache.runes[key] = runes
		cache.bytes += cost
	}
	return runes
}
