package network

import "container/list"

const resourceHashCacheCapacity = 4096

type resourceHashEntry struct {
	key  [32]byte
	hash string
}

// ResourceHash 读取当前客户端的资源哈希。键只保存摘要，不保留 URL、认证头或 Cookie。
// 资源内容受会话影响，因此缓存随客户端释放，不能跨 Engine 复用。
func (c *HTTPClient) ResourceHash(key [32]byte) (string, bool) {
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	if c.closed.Load() {
		return "", false
	}
	elem, ok := c.resourceHashes[key]
	if !ok {
		return "", false
	}
	c.resourceOrder.MoveToFront(elem)
	return elem.Value.(resourceHashEntry).hash, true
}

// StoreResourceHash 保存成功读取的资源哈希，最多保留 4096 条；失败不缓存。
func (c *HTTPClient) StoreResourceHash(key [32]byte, hash string) {
	if hash == "" || hash == "0" {
		return
	}
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	if c.closed.Load() {
		return
	}
	if c.resourceHashes == nil {
		c.resourceHashes = make(map[[32]byte]*list.Element)
		c.resourceOrder = list.New()
	}
	if elem, ok := c.resourceHashes[key]; ok {
		elem.Value = resourceHashEntry{key, hash}
		c.resourceOrder.MoveToFront(elem)
		return
	}
	c.resourceHashes[key] = c.resourceOrder.PushFront(resourceHashEntry{key, hash})
	if len(c.resourceHashes) > resourceHashCacheCapacity {
		oldest := c.resourceOrder.Back()
		delete(c.resourceHashes, oldest.Value.(resourceHashEntry).key)
		c.resourceOrder.Remove(oldest)
	}
}
