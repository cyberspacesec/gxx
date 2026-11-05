package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chainreactors/proxyclient"
)

// 代理协议方案。gxx 支持直连、HTTP(S) CONNECT 以及 SOCKS5/SOCKS5h。
// SOCKS5h 与 SOCKS5 的唯一区别是由代理解析目标域名（远程 DNS）；gxx 的 SOCKS5
// 请求始终以域名（FQDN）形式发送目标，因此两者行为一致，socks5h 归一化为 socks5。
const (
	schemeDirect  = ""
	schemeHTTP    = "http"
	schemeHTTPS   = "https"
	schemeSOCKS5  = "socks5"
	schemeSOCKS5h = "socks5h"
	schemeSOCKS4  = "socks4"
	schemeSOCKS4a = "socks4a"
)

// normalizeProxyURL 解析并归一化代理地址：
//   - 空字符串表示直连；
//   - socks5h 归一化为 socks5（远程 DNS 语义由 SOCKS5 FQDN 请求天然满足），
//     使底层 proxyclient 能识别该方案（它未注册 socks5h）；
//   - 其余方案原样保留，由调用方按需校验。
func normalizeProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("代理地址解析失败: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("代理地址缺少主机: %q", raw)
	}
	switch strings.ToLower(u.Scheme) {
	case schemeSOCKS5h:
		// 克隆后改写，避免影响调用方持有的原始 URL。
		clone := *u
		clone.Scheme = schemeSOCKS5
		return &clone, nil
	case schemeHTTP, schemeHTTPS, schemeSOCKS5, schemeSOCKS4, schemeSOCKS4a, "socks", "socks5+tls":
		return u, nil
	default:
		return nil, fmt.Errorf("不支持的代理协议: %q（支持 http/https/socks5/socks5h/socks4/socks4a）", u.Scheme)
	}
}

// ValidateProxyURL 校验代理地址是否受支持，返回归一化后的 URL。空字符串视为直连（返回 nil, nil）。
func ValidateProxyURL(raw string) (*url.URL, error) {
	return normalizeProxyURL(raw)
}

// proxyBaseScheme 返回代理的基础协议（小写、去掉 +tls 等后缀）。
func proxyBaseScheme(u *url.URL) string {
	if u == nil {
		return schemeDirect
	}
	scheme := strings.ToLower(u.Scheme)
	if i := strings.IndexByte(scheme, '+'); i >= 0 {
		scheme = scheme[:i]
	}
	return scheme
}

// isUDPNetwork 判断网络类型是否为 UDP。
func isUDPNetwork(network string) bool {
	switch strings.ToLower(network) {
	case "udp", "udp4", "udp6":
		return true
	}
	return false
}

// dialThroughProxy 按网络类型与代理方案建立连接：
//   - 直连：net.Dialer；
//   - TCP：HTTP CONNECT 或 SOCKS5，由 proxyclient 处理；
//   - UDP：仅 SOCKS5 支持（UDP ASSOCIATE，自实现），HTTP/SOCKS4 明确报错。
//
// 调用方负责设置整体超时的 ctx；timeout 为单次拨号超时。
func dialThroughProxy(ctx context.Context, network, address string, proxy *url.URL, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	if proxy == nil {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, address)
	}
	if isUDPNetwork(network) {
		switch proxyBaseScheme(proxy) {
		case schemeSOCKS5:
			return dialSOCKS5UDP(ctx, proxy, address, timeout)
		case schemeHTTP, schemeHTTPS:
			return nil, fmt.Errorf("HTTP(S) 代理不支持 UDP（请使用 socks5/socks5h 代理）")
		default:
			return nil, fmt.Errorf("%s 代理不支持 UDP（仅 socks5/socks5h 支持）", proxyBaseScheme(proxy))
		}
	}
	dial, err := proxyclient.NewClient(proxy)
	if err != nil {
		return nil, fmt.Errorf("创建代理客户端失败: %w", err)
	}
	return dial.DialContext(ctx, network, address)
}

// ───────────────────────── SOCKS5 UDP ASSOCIATE ─────────────────────────
//
// proxyclient 的 SOCKS5 UDP 实现会丢弃服务端返回的中继地址、仍返回 TCP 控制连接，
// 导致 UDP 数据被写到控制通道而无法到达目标。gxx 在此自行实现 RFC 1928 的
// UDP ASSOCIATE：保持 TCP 控制连接存活，另建 UDP 套接字到中继地址，并对每个
// 数据报封装/剥离 SOCKS5 UDP 头。

const (
	socks5Version    = 0x05
	socks5CmdUDP     = 0x03
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
	socks5AuthNone   = 0x00
	socks5AuthUserPw = 0x02
)

// socks5UDPConn 把 UDP 数据报经 SOCKS5 中继收发，对外表现为面向单个目标地址的 net.Conn。
// 控制连接（ctrl）必须在整个关联期间保持打开，关闭即释放中继。
type socks5UDPConn struct {
	ctrl   net.Conn // TCP 控制连接，保持关联存活
	relay  net.Conn // 到中继的 UDP 连接
	header []byte   // 预构造的目标地址 SOCKS5 UDP 头（RSV FRAG ATYP ADDR PORT）
}

func dialSOCKS5UDP(ctx context.Context, proxy *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	host, port, err := splitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("解析 UDP 目标地址失败: %w", err)
	}
	ctrl, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 代理失败: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(deadline)
	} else if timeout > 0 {
		_ = ctrl.SetDeadline(time.Now().Add(timeout))
	}
	if proxyBaseScheme(proxy) == schemeSOCKS5 && strings.HasSuffix(strings.ToLower(proxy.Scheme), "+tls") {
		tlsConn := tls.Client(ctrl, &tls.Config{ServerName: proxy.Hostname(), InsecureSkipVerify: true})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = ctrl.Close()
			return nil, err
		}
		ctrl = tlsConn
	}
	if err = socks5Handshake(ctrl, proxy.User); err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	// UDP ASSOCIATE：DST 用 0.0.0.0:0 表示客户端源地址未知，由中继接受任意来源。
	relayAddr, err := socks5UDPAssociate(ctrl, proxy.Hostname())
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	udpConn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", relayAddr)
	if err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("连接 SOCKS5 UDP 中继失败: %w", err)
	}
	header, err := socks5UDPHeader(host, port)
	if err != nil {
		_ = ctrl.Close()
		_ = udpConn.Close()
		return nil, err
	}
	// 控制连接不再需要读写截止时间，清除以免影响保活。
	_ = ctrl.SetDeadline(time.Time{})
	return &socks5UDPConn{ctrl: ctrl, relay: udpConn, header: header}, nil
}

// socks5Handshake 完成方法协商与可选的用户名/密码认证（RFC 1929）。
func socks5Handshake(conn net.Conn, user *url.Userinfo) error {
	method := byte(socks5AuthNone)
	var username, password string
	if user != nil && user.Username() != "" {
		username = user.Username()
		password, _ = user.Password()
		method = socks5AuthUserPw
	}
	if _, err := conn.Write([]byte{socks5Version, 0x01, method}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != socks5Version {
		return fmt.Errorf("SOCKS5 版本不匹配: %d", reply[0])
	}
	switch reply[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthUserPw:
		if method != socks5AuthUserPw {
			return errors.New("SOCKS5 代理要求认证但未提供凭据")
		}
		return socks5UserPassAuth(conn, username, password)
	default:
		return fmt.Errorf("SOCKS5 代理拒绝了所有认证方法 (0x%02x)", reply[1])
	}
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("SOCKS5 用户名或密码过长")
	}
	request := make([]byte, 0, 3+len(username)+len(password))
	request = append(request, 0x01, byte(len(username)))
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return errors.New("SOCKS5 用户名/密码认证失败")
	}
	return nil
}

// socks5UDPAssociate 发送 UDP ASSOCIATE 请求并返回中继地址。
// 中继地址为未指定地址（0.0.0.0 / ::）时回退使用代理主机地址。
func socks5UDPAssociate(conn net.Conn, proxyHost string) (string, error) {
	// VER CMD RSV ATYP=IPv4 0.0.0.0 PORT=0
	request := []byte{socks5Version, socks5CmdUDP, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(request); err != nil {
		return "", err
	}
	reader := bufio.NewReader(conn)
	head := make([]byte, 4)
	if _, err := io.ReadFull(reader, head); err != nil {
		return "", err
	}
	if head[0] != socks5Version {
		return "", fmt.Errorf("SOCKS5 版本不匹配: %d", head[0])
	}
	if head[1] != 0x00 {
		return "", fmt.Errorf("SOCKS5 UDP ASSOCIATE 失败 (状态 0x%02x)", head[1])
	}
	host, err := readSOCKS5Host(reader, head[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = proxyHost
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSOCKS5Host(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socks5AtypDomain:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("SOCKS5 返回了不支持的地址类型: %d", atyp)
	}
}

// socks5UDPHeader 构造目标地址对应的 SOCKS5 UDP 请求头。
// 目标为 IP 时按 IPv4/IPv6 编码，否则按域名编码，使中继执行远程 DNS 解析。
func socks5UDPHeader(host string, port uint16) ([]byte, error) {
	header := []byte{0x00, 0x00, 0x00} // RSV RSV FRAG
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			header = append(header, socks5AtypIPv4)
			header = append(header, v4...)
		} else {
			header = append(header, socks5AtypIPv6)
			header = append(header, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("UDP 目标域名过长: %q", host)
		}
		header = append(header, socks5AtypDomain, byte(len(host)))
		header = append(header, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(header, portBytes...), nil
}

// splitHostPort 拆分 host:port，端口返回为 uint16。
func splitHostPort(address string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("端口无效: %q", portStr)
	}
	return host, uint16(port), nil
}

// Write 把一个数据报经中继发往固定目标：封装 SOCKS5 UDP 头后作为单个数据报发送。
func (c *socks5UDPConn) Write(p []byte) (int, error) {
	packet := make([]byte, 0, len(c.header)+len(p))
	packet = append(packet, c.header...)
	packet = append(packet, p...)
	if _, err := c.relay.Write(packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read 从中继读取一个数据报并剥离 SOCKS5 UDP 头，返回负载。
func (c *socks5UDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+262) // 为头部预留空间（最大 262 字节）
	n, err := c.relay.Read(buf)
	if err != nil {
		return 0, err
	}
	payload, perr := stripSOCKS5UDPHeader(buf[:n])
	if perr != nil {
		return 0, perr
	}
	return copy(p, payload), nil
}

// stripSOCKS5UDPHeader 去除响应数据报的 SOCKS5 UDP 头，返回负载切片。
func stripSOCKS5UDPHeader(packet []byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, errors.New("SOCKS5 UDP 响应过短")
	}
	offset := 4 // RSV RSV FRAG ATYP
	switch packet[3] {
	case socks5AtypIPv4:
		offset += 4
	case socks5AtypIPv6:
		offset += 16
	case socks5AtypDomain:
		if len(packet) < 5 {
			return nil, errors.New("SOCKS5 UDP 响应域名长度缺失")
		}
		offset += 1 + int(packet[4])
	default:
		return nil, fmt.Errorf("SOCKS5 UDP 响应地址类型无效: %d", packet[3])
	}
	offset += 2 // 端口
	if len(packet) < offset {
		return nil, errors.New("SOCKS5 UDP 响应头不完整")
	}
	return packet[offset:], nil
}

func (c *socks5UDPConn) Close() error {
	err := c.relay.Close()
	if cerr := c.ctrl.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

func (c *socks5UDPConn) LocalAddr() net.Addr  { return c.relay.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr { return c.relay.RemoteAddr() }

// SetDeadline 同时作用于控制连接与中继连接的读写截止时间。
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.relay.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }
