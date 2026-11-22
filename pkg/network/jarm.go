package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// JARM 按 salesforce/jarm 公开的算法实现：向目标依次发送 10 个参数不同的 ClientHello，
// 记录服务端在 ServerHello 中选定的套件、版本、ALPN 与扩展列表，再折算成 62 位指纹。
// 探测报文与解析规则（含对畸形响应的处理）逐项与参考实现一致，由测试向量核对。

// jarmEmpty 是目标没有以 TLS 响应时的指纹。
const jarmEmpty = "00000000000000000000000000000000000000000000000000000000000000"

// jarmReadSize 与参考实现一次读取的上限相同。
const jarmReadSize = 1484

type jarmProbe struct {
	version        string // TLS_1.1 / TLS_1.2 / TLS_1.3
	cipherList     string // ALL / NO1.3
	cipherOrder    string // FORWARD / REVERSE / TOP_HALF / BOTTOM_HALF / MIDDLE_OUT
	grease         bool
	rareALPN       bool
	support        string // 1.2_SUPPORT / NO_SUPPORT / 1.3_SUPPORT
	extensionOrder string // FORWARD / REVERSE
}

// jarmProbes 是参考实现的 10 个探测，顺序不能改变。
var jarmProbes = [10]jarmProbe{
	{"TLS_1.2", "ALL", "FORWARD", false, false, "1.2_SUPPORT", "REVERSE"},
	{"TLS_1.2", "ALL", "REVERSE", false, false, "1.2_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "TOP_HALF", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "BOTTOM_HALF", false, true, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.2", "ALL", "MIDDLE_OUT", true, true, "NO_SUPPORT", "REVERSE"},
	{"TLS_1.1", "ALL", "FORWARD", false, false, "NO_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "FORWARD", false, false, "1.3_SUPPORT", "REVERSE"},
	{"TLS_1.3", "ALL", "REVERSE", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "NO1.3", "FORWARD", false, false, "1.3_SUPPORT", "FORWARD"},
	{"TLS_1.3", "ALL", "MIDDLE_OUT", true, false, "1.3_SUPPORT", "REVERSE"},
}

// jarmCiphersAll 是 ALL 列表；NO1.3 去掉其中的 TLS 1.3 套件。
var jarmCiphersAll = []uint16{
	0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045, 0x00be, 0x0088,
	0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072,
	0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060,
	0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304, 0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0,
	0x009c, 0x0035, 0x003d, 0xc09d, 0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
}

// jarmCipherIndex 是指纹中套件的编号表（从 1 开始），与探测列表的顺序不同。
var jarmCipherIndex = []uint16{
	0x0004, 0x0005, 0x0007, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d, 0x0041, 0x0045, 0x0067,
	0x006b, 0x0084, 0x0088, 0x009a, 0x009c, 0x009d, 0x009e, 0x009f, 0x00ba, 0x00be, 0x00c0, 0x00c4, 0xc007, 0xc008,
	0xc009, 0xc00a, 0xc011, 0xc012, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030,
	0xc060, 0xc061, 0xc072, 0xc073, 0xc076, 0xc077, 0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1, 0xc0a2, 0xc0a3,
	0xc0ac, 0xc0ad, 0xc0ae, 0xc0af, 0xcc13, 0xcc14, 0xcca8, 0xcca9, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
}

var jarmGrease = [16]uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}

var (
	jarmALPN     = []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq"}
	jarmRareALPN = []string{"http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq"}
)

// jarmRandom 提供探测报文中的随机字段：random、会话标识、密钥分享与 GREASE。
type jarmRandom interface {
	bytes(n int) []byte
	grease() uint16
}

type cryptoRandom struct{}

func (cryptoRandom) bytes(n int) []byte {
	out := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, out)
	return out
}

func (cryptoRandom) grease() uint16 {
	var b [1]byte
	_, _ = io.ReadFull(rand.Reader, b[:])
	return jarmGrease[b[0]&0x0f]
}

// jarmMung 按参考实现的 cipher_mung 调整顺序。
func jarmMung[T any](items []T, order string) []T {
	n := len(items)
	switch order {
	case "REVERSE":
		out := make([]T, n)
		for i, item := range items {
			out[n-1-i] = item
		}
		return out
	case "BOTTOM_HALF":
		if n%2 == 1 {
			return append([]T(nil), items[n/2+1:]...)
		}
		return append([]T(nil), items[n/2:]...)
	case "TOP_HALF":
		var out []T
		if n%2 == 1 {
			out = append(out, items[n/2])
		}
		return append(out, jarmMung(jarmMung(items, "REVERSE"), "BOTTOM_HALF")...)
	case "MIDDLE_OUT":
		middle := n / 2
		var out []T
		if n%2 == 1 {
			out = append(out, items[middle])
			for i := 1; i <= middle; i++ {
				out = append(out, items[middle+i], items[middle-i])
			}
		} else {
			for i := 1; i <= middle; i++ {
				out = append(out, items[middle-1+i], items[middle-i])
			}
		}
		return out
	}
	return items
}

// jarmClientHello 构造一个探测报文（记录层 + ClientHello），与参考实现的 packet_building 一致。
func jarmClientHello(host string, probe jarmProbe, rnd jarmRandom) []byte {
	recordVersion, helloVersion := uint16(0x0303), uint16(0x0303)
	switch probe.version {
	case "TLS_1.3":
		recordVersion = 0x0301
	case "TLS_1.1":
		recordVersion, helloVersion = 0x0302, 0x0302
	}
	hello := binary.BigEndian.AppendUint16(nil, helloVersion)
	hello = append(hello, rnd.bytes(32)...)
	hello = append(hello, 32)
	hello = append(hello, rnd.bytes(32)...)

	ciphers := jarmCiphersAll
	if probe.cipherList == "NO1.3" {
		ciphers = make([]uint16, 0, len(jarmCiphersAll))
		for _, suite := range jarmCiphersAll {
			if suite>>8 != 0x13 {
				ciphers = append(ciphers, suite)
			}
		}
	}
	if probe.cipherOrder != "FORWARD" {
		ciphers = jarmMung(ciphers, probe.cipherOrder)
	}
	if probe.grease {
		ciphers = append([]uint16{rnd.grease()}, ciphers...)
	}
	hello = binary.BigEndian.AppendUint16(hello, uint16(2*len(ciphers)))
	for _, suite := range ciphers {
		hello = binary.BigEndian.AppendUint16(hello, suite)
	}
	hello = append(hello, 0x01, 0x00) // 压缩方法：一种，null
	hello = append(hello, jarmExtensions(host, probe, rnd)...)

	handshake := append([]byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	record := []byte{0x16}
	record = binary.BigEndian.AppendUint16(record, recordVersion)
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	return append(record, handshake...)
}

func jarmExtensions(host string, probe jarmProbe, rnd jarmRandom) []byte {
	var ext []byte
	if probe.grease {
		ext = binary.BigEndian.AppendUint16(ext, rnd.grease())
		ext = append(ext, 0x00, 0x00)
	}
	// server_name
	ext = append(ext, 0x00, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)+5))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)+3))
	ext = append(ext, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(host)))
	ext = append(ext, host...)
	ext = append(ext, 0x00, 0x17, 0x00, 0x00)                                                             // extended_master_secret
	ext = append(ext, 0x00, 0x01, 0x00, 0x01, 0x01)                                                       // max_fragment_length
	ext = append(ext, 0xff, 0x01, 0x00, 0x01, 0x00)                                                       // renegotiation_info
	ext = append(ext, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19) // supported_groups
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)                                                 // ec_point_formats
	ext = append(ext, 0x00, 0x23, 0x00, 0x00)                                                             // session_ticket

	alpns := jarmALPN
	if probe.rareALPN {
		alpns = jarmRareALPN
	}
	if probe.extensionOrder != "FORWARD" {
		alpns = jarmMung(alpns, probe.extensionOrder)
	}
	var protocols []byte
	for _, name := range alpns {
		protocols = append(protocols, byte(len(name)))
		protocols = append(protocols, name...)
	}
	ext = append(ext, 0x00, 0x10)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(protocols)+2))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(protocols)))
	ext = append(ext, protocols...)

	ext = append(ext, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01) // signature_algorithms

	// key_share：GREASE 占位之后是一个 x25519 随机公钥。
	var share []byte
	if probe.grease {
		share = binary.BigEndian.AppendUint16(share, rnd.grease())
		share = append(share, 0x00, 0x01, 0x00)
	}
	share = append(share, 0x00, 0x1d, 0x00, 0x20)
	share = append(share, rnd.bytes(32)...)
	ext = append(ext, 0x00, 0x33)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(share)+2))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(share)))
	ext = append(ext, share...)

	ext = append(ext, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01) // psk_key_exchange_modes

	if probe.version == "TLS_1.3" || probe.support == "1.2_SUPPORT" {
		versions := []uint16{0x0301, 0x0302, 0x0303}
		if probe.support != "1.2_SUPPORT" {
			versions = append(versions, 0x0304)
		}
		if probe.extensionOrder != "FORWARD" {
			versions = jarmMung(versions, probe.extensionOrder)
		}
		var list []byte
		if probe.grease {
			list = binary.BigEndian.AppendUint16(list, rnd.grease())
		}
		for _, version := range versions {
			list = binary.BigEndian.AppendUint16(list, version)
		}
		ext = append(ext, 0x00, 0x2b)
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(list)+1))
		ext = append(ext, byte(len(list)))
		ext = append(ext, list...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(ext))), ext...)
}

// errJARMMalformed 表示响应无法按参考实现解析，对应 "|||"。
var errJARMMalformed = errors.New("jarm: malformed")

// pySlice 按 Python 切片的语义取 data[from:to]，越界部分截断而不报错。
func pySlice(data []byte, from, to int) []byte {
	from, to = min(max(from, 0), len(data)), min(max(to, 0), len(data))
	if from >= to {
		return nil
	}
	return data[from:to]
}

// pyHexInt 按 int(hex, 16) 解析字节；空字节串在参考实现中会抛出异常。
func pyHexInt(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errJARMMalformed
	}
	value := 0
	for _, c := range b {
		value = value<<8 | int(c)
	}
	return value, nil
}

// jarmParse 按参考实现的 read_packet 解析一次探测的响应，返回 "套件|版本|ALPN|扩展"。
func jarmParse(data []byte) string {
	raw, err := jarmParseStrict(data)
	if err != nil {
		return "|||"
	}
	return raw
}

func jarmParseStrict(data []byte) (string, error) {
	if len(data) == 0 || data[0] == 21 {
		return "", errJARMMalformed
	}
	if len(data) < 6 || data[0] != 22 || data[5] != 2 {
		return "", errJARMMalformed
	}
	helloLength, _ := pyHexInt(pySlice(data, 3, 5))
	if len(data) < 44 {
		return "", errJARMMalformed
	}
	counter := int(data[43])
	raw := hex.EncodeToString(pySlice(data, counter+44, counter+46)) + "|" + hex.EncodeToString(pySlice(data, 9, 11)) + "|"
	extensions, err := jarmExtensionInfo(data, counter, helloLength)
	if err != nil {
		return "", err
	}
	return raw + extensions, nil
}

// jarmExtensionInfo 按参考实现的 extract_extension_info 提取 ALPN 与扩展类型。
// 参考实现中下标越界返回 "|"，其他异常使整次探测记为 "|||"。
func jarmExtensionInfo(data []byte, counter, helloLength int) (string, error) {
	if counter+47 >= len(data) {
		return "|", nil
	}
	if data[counter+47] == 11 || string(pySlice(data, counter+50, counter+53)) == "\x0e\xac\x0b" || string(pySlice(data, 82, 85)) == "\x0f\xf0\x0b" || counter+42 >= helloLength {
		return "|", nil
	}
	count := 49 + counter
	length, err := pyHexInt(pySlice(data, counter+47, counter+49))
	if err != nil {
		return "", err
	}
	maximum := length + count - 1
	var types, values [][]byte
	var empty []bool
	for count < maximum {
		types = append(types, pySlice(data, count, count+2))
		size, err := pyHexInt(pySlice(data, count+2, count+4))
		if err != nil {
			return "", err
		}
		if size == 0 {
			count += 4
			values = append(values, nil)
			empty = append(empty, true)
		} else {
			values = append(values, pySlice(data, count+4, count+4+size))
			empty = append(empty, false)
			count += size + 4
		}
	}
	alpn := ""
	for i, kind := range types {
		if string(kind) == "\x00\x10" {
			// 参考实现对空值调用 decode 会抛出异常，非 UTF-8 的协议名同样如此。
			if empty[i] || !utf8.Valid(pySlice(values[i], 3, len(values[i]))) {
				return "", errJARMMalformed
			}
			alpn = string(pySlice(values[i], 3, len(values[i])))
			break
		}
	}
	names := make([]string, len(types))
	for i, kind := range types {
		names[i] = hex.EncodeToString(kind)
	}
	return alpn + "|" + strings.Join(names, "-"), nil
}

// JARMHash 把 10 次探测的原始结果折算成 62 位指纹：前 30 位是各次套件编号与版本，
// 后 32 位是 ALPN 与扩展列表的 SHA256 前缀。全部探测都没有结果时为 62 个 0。
func JARMHash(raw string) string {
	if raw == "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||" {
		return jarmEmpty
	}
	var fuzzy, alpnAndExtensions strings.Builder
	for _, handshake := range strings.Split(raw, ",") {
		parts := strings.Split(handshake, "|")
		for len(parts) < 4 {
			parts = append(parts, "")
		}
		fuzzy.WriteString(jarmCipherByte(parts[0]))
		fuzzy.WriteString(jarmVersionByte(parts[1]))
		alpnAndExtensions.WriteString(parts[2])
		alpnAndExtensions.WriteString(parts[3])
	}
	sum := sha256.Sum256([]byte(alpnAndExtensions.String()))
	return fuzzy.String() + hex.EncodeToString(sum[:])[:32]
}

func jarmCipherByte(cipher string) string {
	if cipher == "" {
		return "00"
	}
	count := len(jarmCipherIndex) + 1
	for i, suite := range jarmCipherIndex {
		if hex.EncodeToString([]byte{byte(suite >> 8), byte(suite)}) == cipher {
			count = i + 1
			break
		}
	}
	text := strconv.FormatInt(int64(count), 16)
	if len(text) < 2 {
		text = "0" + text
	}
	return text
}

func jarmVersionByte(version string) string {
	if version == "" {
		return "0"
	}
	if len(version) < 4 || version[3] < '0' || version[3] > '5' {
		return "0"
	}
	return string("abcdef"[version[3]-'0'])
}

// JARM 计算 host:port 的 JARM 指纹。每次探测都经过网络策略（CheckTarget、Dial、代理）
// 与限速，SNI 使用 host。连接或读取超时时按参考实现返回 62 个 0。
func (c *HTTPClient) JARM(ctx context.Context, host, port string, options OptionsRequest) (string, error) {
	setDefaults(&options)
	ctx = withKind(ctx, RequestTLS)
	policy := c.PolicyFor(ctx)
	info := RequestInfoFrom(ctx)
	address := net.JoinHostPort(host, port)
	results := make([]string, 0, len(jarmProbes))
	for _, probe := range jarmProbes {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		target := addressTarget(RequestTLS, "tcp", address, info)
		target.Host = host
		if err := checkTarget(ctx, policy, target); err != nil {
			return "", err
		}
		if err := c.WaitRequest(ctx, "tls://"+address); err != nil {
			return "", err
		}
		data, err := c.jarmExchange(ctx, policy, host, address, probe, options)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, context.DeadlineExceeded) {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				return jarmEmpty, nil
			}
		}
		results = append(results, jarmParse(data))
	}
	return JARMHash(strings.Join(results, ",")), nil
}

// jarmExchange 发送一个探测并读取响应，至少读到第一条完整的 TLS 记录（最多 1484 字节）。
func (c *HTTPClient) jarmExchange(ctx context.Context, policy Policy, host, address string, probe jarmProbe, options OptionsRequest) ([]byte, error) {
	rec := RecorderFrom(ctx)
	start := time.Now()
	info := RequestInfoFrom(ctx)
	ex := Exchange{Kind: RequestTLS, RuleID: info.RuleID, SubRule: info.SubRule, URL: "tls://" + address}
	conn, err := dialTarget(ctx, policy, nil, "tcp", address, options.Proxy, options.Timeout, false, "", true)
	if err != nil {
		rec.Data(ex, nil, start, err)
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))
	if _, err := conn.Write(jarmClientHello(host, probe, cryptoRandom{})); err != nil {
		rec.Data(ex, nil, start, err)
		return nil, err
	}
	buf := make([]byte, jarmReadSize)
	read := 0
	for read < len(buf) {
		n, err := conn.Read(buf[read:])
		read += n
		if read >= 5 && read >= 5+int(binary.BigEndian.Uint16(buf[3:5])) {
			break
		}
		if err != nil {
			// 已经收到数据时按收到的部分解析，与参考实现单次读取的结果一致；
			// 一个字节都没有收到时把错误交给调用方区分超时与连接失败。
			if read > 0 {
				break
			}
			rec.Data(ex, nil, start, err)
			return nil, err
		}
	}
	rec.Data(ex, buf[:read], start, nil)
	return buf[:read], nil
}
