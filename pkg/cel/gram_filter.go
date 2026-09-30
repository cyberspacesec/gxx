package cel

import (
	"bytes"
	"math/bits"
)

const gramFilterBytes = 8 << 10

// gramFilter 用固定 8 KiB 位图记录响应中的 4 字节片段。散列冲突只增加
// 候选，不会排除真实匹配；最终结果始终由原始包含函数判断。
type gramFilter [gramFilterBytes / 8]uint64

func gramHash(word uint32) uint16 {
	return uint16((uint64(word) * 0x9e3779b97f4a7c15) >> 48)
}

func newGramFilter(data []byte) *gramFilter {
	f := new(gramFilter)
	var word uint32
	for i, c := range data {
		word = word<<8 | uint32(c)
		if i >= 3 {
			hash := gramHash(word)
			f[hash/64] |= uint64(1) << (hash % 64)
		}
	}
	occupied := 0
	for _, word := range f {
		occupied += bits.OnesCount64(word)
	}
	// 随机二进制响应可能使位图饱和，此时直接匹配更合适。
	if occupied > gramFilterBytes*8*3/4 {
		return nil
	}
	return f
}

func (f *gramFilter) mayContain(needle []byte, fold bool) bool {
	if fold {
		needle = bytes.ToLower(needle)
	}
	var word uint32
	for i, c := range needle {
		word = word<<8 | uint32(c)
		if i >= 3 {
			hash := gramHash(word)
			if f[hash/64]&(uint64(1)<<(hash%64)) == 0 {
				return false
			}
		}
	}
	return true
}
