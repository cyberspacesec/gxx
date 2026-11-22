package network

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
)

// ServerHello 是服务端握手首条消息中用于指纹的字段。
type ServerHello struct {
	Version     uint16   // legacy_version，TLS 1.3 时为 0x0303
	CipherSuite uint16   // 服务端选定的套件
	Extensions  []uint16 // 扩展类型，按服务端发送的顺序
}

// JA3SString 按公开的 JA3S 定义返回 "SSLVersion,Cipher,SSLExtension"：三段均为十进制，
// 扩展类型按出现顺序以 "-" 连接；不剔除任何扩展值。
func (h ServerHello) JA3SString() string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(h.Version)))
	b.WriteByte(',')
	b.WriteString(strconv.Itoa(int(h.CipherSuite)))
	b.WriteByte(',')
	for i, ext := range h.Extensions {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(ext)))
	}
	return b.String()
}

// JA3S 返回 JA3S 字符串的 MD5 十六进制摘要。
func (h ServerHello) JA3S() string {
	sum := md5.Sum([]byte(h.JA3SString()))
	return hex.EncodeToString(sum[:])
}

// helloRetryRandom 是 TLS 1.3 HelloRetryRequest 固定的 random 值（RFC 8446 4.1.3）。
var helloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

var errNotServerHello = errors.New("不是 ServerHello 消息")

// ParseServerHello 解析一条完整的 ServerHello 握手消息（含 4 字节握手头）。
func ParseServerHello(message []byte) (ServerHello, bool, error) {
	var hello ServerHello
	if len(message) < 4 || message[0] != 2 {
		return hello, false, errNotServerHello
	}
	length := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	body := message[4:]
	if len(body) < length {
		return hello, false, errors.New("ServerHello 不完整")
	}
	body = body[:length]
	// legacy_version(2) random(32) session_id(1+n) cipher(2) compression(1) [extensions(2+n)]
	if len(body) < 38 {
		return hello, false, errors.New("ServerHello 过短")
	}
	hello.Version = binary.BigEndian.Uint16(body)
	retry := bytes.Equal(body[2:34], helloRetryRandom)
	at := 34
	sessionLen := int(body[at])
	at++
	if len(body) < at+sessionLen+3 {
		return hello, retry, errors.New("ServerHello 会话标识越界")
	}
	at += sessionLen
	hello.CipherSuite = binary.BigEndian.Uint16(body[at:])
	at += 3
	if at == len(body) {
		return hello, retry, nil
	}
	if len(body) < at+2 {
		return hello, retry, errors.New("ServerHello 扩展长度缺失")
	}
	extLen := int(binary.BigEndian.Uint16(body[at:]))
	at += 2
	if len(body) < at+extLen {
		return hello, retry, errors.New("ServerHello 扩展越界")
	}
	exts := body[at : at+extLen]
	for len(exts) > 0 {
		if len(exts) < 4 {
			return hello, retry, errors.New("ServerHello 扩展头不完整")
		}
		size := int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+size {
			return hello, retry, errors.New("ServerHello 扩展内容越界")
		}
		hello.Extensions = append(hello.Extensions, binary.BigEndian.Uint16(exts))
		exts = exts[4+size:]
	}
	return hello, retry, nil
}

// maxHelloCapture 限制旁路记录的握手字节；ServerHello 远小于该值。
const maxHelloCapture = 16 << 10

// helloRecorder 位于 TLS 之下，旁路记录服务端发来的握手记录，解析出 ServerHello 后停止。
// 只读取 TLS 本来就会读取的字节，不改变握手，也不增加连接。
type helloRecorder struct {
	net.Conn
	mu        sync.Mutex
	records   []byte // 尚未凑齐的记录层字节
	handshake []byte // 握手层字节
	done      bool
	hello     ServerHello
	found     bool
}

func (r *helloRecorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if !r.done {
			r.feed(p[:n])
		}
		r.mu.Unlock()
	}
	return n, err
}

// feed 按记录层拆分，只累积握手类型（22）的记录，凑齐一条非 HelloRetryRequest 的
// ServerHello 后停止。遇到其他类型的记录或超出上限即停止记录。
func (r *helloRecorder) feed(data []byte) {
	r.records = append(r.records, data...)
	for len(r.records) >= 5 {
		length := int(binary.BigEndian.Uint16(r.records[3:5]))
		if len(r.records) < 5+length {
			break
		}
		if r.records[0] != 22 {
			r.done = true
			break
		}
		r.handshake = append(r.handshake, r.records[5:5+length]...)
		r.records = r.records[5+length:]
		for len(r.handshake) >= 4 {
			size := 4 + (int(r.handshake[1])<<16 | int(r.handshake[2])<<8 | int(r.handshake[3]))
			if len(r.handshake) < size {
				break
			}
			if r.handshake[0] != 2 {
				r.done = true
				break
			}
			hello, retry, err := ParseServerHello(r.handshake[:size])
			r.handshake = r.handshake[size:]
			if err != nil {
				r.done = true
				break
			}
			r.hello, r.found = hello, true
			if !retry {
				r.done = true
				break
			}
		}
		if r.done {
			break
		}
	}
	if r.done || len(r.records)+len(r.handshake) > maxHelloCapture {
		r.done = true
		r.records, r.handshake = nil, nil
	}
}

// serverHello 返回记录到的 ServerHello。
func (r *helloRecorder) serverHello() (ServerHello, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hello, r.found
}

// TLSInfo 是一次 TLS 握手的摘要。
type TLSInfo struct {
	Version     string // 如 "TLS 1.2"
	CipherSuite string // 如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	ALPN        string
	JA3S        string
	JARM        string
}

// tlsSummary 由握手状态与记录到的 ServerHello 生成摘要。
func tlsSummary(state *tls.ConnectionState, hello ServerHello, found bool) TLSInfo {
	var info TLSInfo
	if state != nil {
		info.Version = tls.VersionName(state.Version)
		info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		info.ALPN = state.NegotiatedProtocol
	}
	if found {
		info.JA3S = hello.JA3S()
	}
	return info
}

// handshakeTLS 在 conn 上完成扫描 TLS 握手，同时旁路记录 ServerHello。
func handshakeTLS(ctx context.Context, conn net.Conn, config *tls.Config) (*tls.Conn, *helloRecorder, error) {
	recorder := &helloRecorder{Conn: conn}
	secure := tls.Client(recorder, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	return secure, recorder, nil
}

// ConnTLSInfo 返回 DialContext 建立的 TLS 连接的握手摘要；明文连接返回 false。
func ConnTLSInfo(conn net.Conn) (TLSInfo, *tls.ConnectionState, bool) {
	switch c := conn.(type) {
	case *trackedConn:
		if c.tls == nil {
			return TLSInfo{}, nil, false
		}
		return c.tls.info, &c.tls.state, true
	case *tls.Conn:
		state := c.ConnectionState()
		var hello ServerHello
		var found bool
		if recorder, ok := c.NetConn().(*helloRecorder); ok {
			hello, found = recorder.serverHello()
		}
		return tlsSummary(&state, hello, found), &state, true
	}
	return TLSInfo{}, nil, false
}
