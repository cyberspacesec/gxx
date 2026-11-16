// Package casefold 提供与 bytes.ToLower 逐字节一致的小写转换。
//
// 标准库对含非 ASCII 字符的输入逐字符查询 Unicode 大小写表。中日韩文字没有
// 大小写，却占据此类页面的大部分字符；这里按码位区间直接跳过它们，ASCII
// 连续段整段复制后原地转换，其余字符仍交给 unicode.ToLower。
package casefold

import (
	"unicode"
	"unicode/utf8"
	"unsafe"
)

const invalidRune = "\uFFFD"

// caseless 报告码位是否落在没有大小写映射的连续区间内：
// U+2E80–U+A63F 覆盖中日韩部首、符号、假名、注音、表意文字、彝文、傈僳文与
// 瓦伊文；U+AC00–U+D7FF 覆盖谚文音节与字母扩展。区间之外一律查表。
func caseless(r rune) bool {
	return r >= 0x2E80 && (r <= 0xA63F || r >= 0xAC00 && r <= 0xD7FF)
}

// Lower 返回 src 的小写形式，内容与 bytes.ToLower(src) 逐字节相同：
// 非法 UTF-8 字节替换为 U+FFFD。无需改写时直接返回 src，不复制；
// 调用方必须把输入和返回值都视为只读。
func Lower(src []byte) []byte {
	i := unchangedPrefix(src)
	if i == len(src) {
		return src
	}
	dst := make([]byte, i, len(src)+utf8.UTFMax)
	copy(dst, src[:i])
	for i < len(src) {
		if src[i] < utf8.RuneSelf {
			end := i + 1
			for end < len(src) && src[end] < utf8.RuneSelf {
				end++
			}
			start := len(dst)
			dst = append(dst, src[i:end]...)
			for k := start; k < len(dst); k++ {
				if c := dst[k]; 'A' <= c && c <= 'Z' {
					dst[k] = c + ('a' - 'A')
				}
			}
			i = end
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			dst = append(dst, invalidRune...)
		case caseless(r):
			dst = append(dst, src[i:i+size]...)
		default:
			if lower := unicode.ToLower(r); lower != r {
				dst = utf8.AppendRune(dst, lower)
			} else {
				dst = append(dst, src[i:i+size]...)
			}
		}
		i += size
	}
	return dst
}

// LowerString 与 Lower 相同，但把结果作为字符串返回且不再复制。
// 无需改写时字符串与 src 共用底层数组，src 在字符串存活期间不得修改。
func LowerString(src []byte) string {
	lowered := Lower(src)
	return unsafe.String(unsafe.SliceData(lowered), len(lowered))
}

// unchangedPrefix 返回 src 中无需改写的前缀长度。
func unchangedPrefix(src []byte) int {
	i := 0
	for i < len(src) {
		c := src[i]
		if c < utf8.RuneSelf {
			if 'A' <= c && c <= 'Z' {
				return i
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		if !caseless(r) && unicode.ToLower(r) != r {
			return i
		}
		i += size
	}
	return i
}
