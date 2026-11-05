package common

import (
	"testing"
	"unicode/utf8"
)

func TestValidUTF8Truncated(t *testing.T) {
	zheng := []byte("证") // e8 af 81
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"空", nil, true},
		{"纯 ASCII", []byte("hello"), true},
		{"完整中文", []byte("统一身份认证"), true},
		{"尾部缺 1 字节(3 字节字符)", append([]byte("统一身份认"), zheng[:2]...), true},
		{"尾部缺 2 字节(3 字节字符)", append([]byte("统一身份认"), zheng[:1]...), true},
		{"尾部缺 3 字节(4 字节字符)", append([]byte("a"), []byte("😀")[:1]...), true},
		{"尾部缺 1 字节(4 字节字符)", append([]byte("a"), []byte("😀")[:3]...), true},
		{"中间有非法字节", []byte{'a', 0xff, 'b'}, false},
		{"中间有截断序列", append(append([]byte("统一"), zheng[:2]...), []byte("abc")...), false},
		{"尾部是非法字节而非截断", []byte{'a', 0xff}, false},
		{"尾部两个孤立的后继字节", []byte{'a', 0x80, 0x80}, false},
		{"GBK 前导字节后接 ASCII", []byte{0xc4, 'a'}, false},
		{"GB18030 汉字", []byte{0xc4, 0xe3, 0xba, 0xc3}, false},
		{"前部是 GB18030、尾部又被截断", []byte{0xc4, 0xe3, 0xba, 0xc3, 0xe8, 0xaf}, false},
		{"过长编码的前缀", []byte{'a', 0xe0, 0x80}, false},
	}
	for _, tc := range cases {
		if got := ValidUTF8Truncated(tc.data); got != tc.want {
			t.Errorf("%s: ValidUTF8Truncated(%x)=%v, want %v", tc.name, tc.data, got, tc.want)
		}
		if got := ValidUTF8TruncatedString(string(tc.data)); got != tc.want {
			t.Errorf("%s: ValidUTF8TruncatedString(%x)=%v, want %v", tc.name, tc.data, got, tc.want)
		}
		if utf8.Valid(tc.data) && !ValidUTF8Truncated(tc.data) {
			t.Errorf("%s: 完整合法的 UTF-8 不能被判为非法", tc.name)
		}
	}
}

func TestStr2UTF8LeavesTruncatedUTF8Untouched(t *testing.T) {
	truncated := string(append([]byte("统一身份认"), []byte("证")[:2]...))
	if got := Str2UTF8(truncated); got != truncated {
		t.Fatalf("末尾被截断的 UTF-8 被改写: %x -> %x", truncated, got)
	}
	if got := Str2UTF8(string([]byte{0xc4, 0xe3, 0xba, 0xc3})); got != "你好" {
		t.Fatalf("GB18030 未被转换: %q", got)
	}
}
