package finger

import (
	"fmt"
	"io"
)

// iconDataReader 逐块解码 URL 转义和 Base64 空白，不创建完整载荷副本。
// 缺少尾部填充的 Base64 在 EOF 时补齐，'+' 始终是原始载荷字符。
type iconDataReader struct {
	payload    string
	encoded    bool
	at         int
	count      int
	padding    int
	ended      bool
	sawPadding bool
}

func (r *iconDataReader) Read(dst []byte) (int, error) {
	n := 0
	for n < len(dst) && r.at < len(r.payload) {
		b := r.payload[r.at]
		r.at++
		if b == '%' {
			if r.at+1 >= len(r.payload) {
				return n, fmt.Errorf("图标数据的 URL 转义不完整")
			}
			hi, lo := iconHex(r.payload[r.at]), iconHex(r.payload[r.at+1])
			if hi < 0 || lo < 0 {
				return n, fmt.Errorf("图标数据的 URL 转义无效")
			}
			b = byte(hi*16 + lo)
			r.at += 2
		}
		if r.encoded && (b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f') {
			continue
		}
		dst[n] = b
		n++
		r.count++
		if b == '=' {
			r.sawPadding = true
		}
	}
	if r.at == len(r.payload) && !r.ended {
		r.ended = true
		if r.encoded && !r.sawPadding && r.count%4 >= 2 {
			r.padding = 4 - r.count%4
		}
	}
	for n < len(dst) && r.padding > 0 {
		dst[n] = '='
		n++
		r.padding--
	}
	if n == 0 && r.ended && r.padding == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func iconHex(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b - 'a' + 10)
	case b >= 'A' && b <= 'F':
		return int(b - 'A' + 10)
	}
	return -1
}
