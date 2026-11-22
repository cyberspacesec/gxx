package network

import "container/list"

const resourceHashCacheCapacity = 4096

// resourceEvidenceBudget 是资源缓存中证据数据（图标原始字节）的总预算，超出时淘汰最旧的条目。
const resourceEvidenceBudget = 16 << 20

// ResourceRecord 是一次成功读取的页面资源。Evidence 由调用方解释（图标证据），
// Size 是它占用的字节数，计入缓存预算。
type ResourceRecord struct {
	Hash     string
	Evidence any
	Size     int
}

type resourceHashEntry struct {
	key    [32]byte
	record ResourceRecord
}

// ResourceHash 读取当前客户端的资源哈希。键只保存摘要，不保留 URL、认证头或 Cookie。
// 资源内容受会话影响，因此缓存随客户端释放，不能跨 Engine 复用。
func (c *HTTPClient) ResourceHash(key [32]byte) (string, bool) {
	record, ok := c.Resource(key)
	return record.Hash, ok
}

// Resource 读取当前客户端缓存的资源记录。
func (c *HTTPClient) Resource(key [32]byte) (ResourceRecord, bool) {
	c.resourceMu.Lock()
	defer c.resourceMu.Unlock()
	if c.closed.Load() {
		return ResourceRecord{}, false
	}
	elem, ok := c.resourceHashes[key]
	if !ok {
		return ResourceRecord{}, false
	}
	c.resourceOrder.MoveToFront(elem)
	return elem.Value.(resourceHashEntry).record, true
}

// StoreResourceHash 保存成功读取的资源哈希，最多保留 4096 条；失败不缓存。
func (c *HTTPClient) StoreResourceHash(key [32]byte, hash string) {
	c.StoreResource(key, ResourceRecord{Hash: hash})
}

// StoreResource 保存成功读取的资源记录，最多保留 4096 条，证据数据合计不超过 16 MiB；
// 哈希为空或为 "0"（读取失败）时不缓存。
func (c *HTTPClient) StoreResource(key [32]byte, record ResourceRecord) {
	if record.Hash == "" || record.Hash == "0" || record.Size > resourceEvidenceBudget {
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
		c.resourceBytes -= elem.Value.(resourceHashEntry).record.Size
		elem.Value = resourceHashEntry{key, record}
		c.resourceOrder.MoveToFront(elem)
	} else {
		c.resourceHashes[key] = c.resourceOrder.PushFront(resourceHashEntry{key, record})
	}
	c.resourceBytes += record.Size
	for len(c.resourceHashes) > resourceHashCacheCapacity || c.resourceBytes > resourceEvidenceBudget {
		oldest := c.resourceOrder.Back()
		entry := oldest.Value.(resourceHashEntry)
		delete(c.resourceHashes, entry.key)
		c.resourceBytes -= entry.record.Size
		c.resourceOrder.Remove(oldest)
	}
}
