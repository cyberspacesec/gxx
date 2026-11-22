package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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
		u.Scheme = schemeSOCKS5
	case schemeHTTP, schemeHTTPS, schemeSOCKS5, schemeSOCKS4, schemeSOCKS4a, "socks", "socks5+tls":
	default:
		return nil, fmt.Errorf("不支持的代理协议: %q（支持 http/https/socks5/socks5h/socks4/socks4a）", u.Scheme)
	}
	// 拨号直接使用 Host，省略端口时按协议补默认端口，否则会报 "missing port in address"。
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), defaultProxyPort(u))
	}
	return u, nil
}

// defaultProxyPort 返回代理协议的默认端口：HTTP 80、HTTPS 443、SOCKS 1080。
func defaultProxyPort(u *url.URL) string {
	switch strings.ToLower(u.Scheme) {
	case schemeHTTP:
		return "80"
	case schemeHTTPS:
		return "443"
	}
	return "1080"
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
//   - 直连：网络策略的 Dial 或 net.Dialer；
//   - TCP：HTTP CONNECT 或 SOCKS5，由 proxyclient 处理，连接代理服务器同样经过策略的 Dial；
//   - UDP：仅 SOCKS5 支持（UDP ASSOCIATE，自实现），HTTP/SOCKS4 明确报错。
//
// 调用方负责设置整体超时的 ctx；timeout 为单次拨号超时。
func dialThroughProxy(ctx context.Context, network, address string, proxy *url.URL, timeout time.Duration, policyDial dialFunc) (net.Conn, error) {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	dial := policyDialer(policyDial, timeout, 0)
	if proxy == nil {
		return dial(ctx, network, address)
	}
	if isUDPNetwork(network) {
		switch proxyBaseScheme(proxy) {
		case schemeSOCKS5:
			return dialSOCKS5UDP(ctx, proxy, address, timeout, dial)
		case schemeHTTP, schemeHTTPS:
			return nil, fmt.Errorf("HTTP(S) 代理不支持 UDP（请使用 socks5/socks5h 代理）")
		default:
			return nil, fmt.Errorf("%s 代理不支持 UDP（仅 socks5/socks5h 支持）", proxyBaseScheme(proxy))
		}
	}
	switch proxyBaseScheme(proxy) {
	case schemeHTTP, schemeHTTPS:
		// HTTP(S) 代理自实现 CONNECT，修正 proxyclient 忽略 ctx/超时、吞掉非 2xx 错误、
		// 丢弃隧道首批缓冲字节的问题。
		return dialHTTPConnect(ctx, network, address, proxy, timeout, dial)
	default:
		// SOCKS4/SOCKS5(+TLS) 仍由 proxyclient 处理，其 Dial 会向上游拨号传递 ctx。
		client, err := proxyclient.NewClientWithDial(applyProxyTLSDefaults(proxy), proxyclient.Dial(dial))
		if err != nil {
			return nil, fmt.Errorf("创建代理客户端失败: %w", err)
		}
		return client.DialContext(ctx, network, address)
	}
}

// prefixConn 在底层连接前插入一段预读字节，保证 CONNECT 响应之后被缓冲的隧道首批数据不丢失。
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// ProxyError 表示代理本身不可用（连不上、不是代理、要求认证），与目标无关：
// 换任何目标都会失败，调用方应当停止而不是逐个目标重试。
type ProxyError struct {
	Proxy string
	Err   error
}

func (e *ProxyError) Error() string { return e.Err.Error() }
func (e *ProxyError) Unwrap() error { return e.Err }

// connectRejected 把代理对 CONNECT 的非 200 响应转成错误。网关类状态（403、502、
// 503、504 等）说明代理在工作、只是到不了这个目标；400、404、405、501 说明对方
// 不认识 CONNECT，即该地址不是 HTTP 代理；407 是代理要求认证。后两类与目标无关。
func connectRejected(proxy string, resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusProxyAuthRequired:
		return &ProxyError{Proxy: proxy, Err: fmt.Errorf("HTTP 代理 %s 要求认证（407），请在代理地址中提供用户名和密码", proxy)}
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return &ProxyError{Proxy: proxy, Err: fmt.Errorf("%s 不是可用的 HTTP 代理：它对 CONNECT 请求返回 %s，该端口上运行的可能是普通 Web 服务", proxy, resp.Status)}
	}
	return fmt.Errorf("HTTP 代理拒绝 CONNECT（状态 %s）", resp.Status)
}

// CheckProxy 经代理向 address（host:port）建立一次连接，只在代理本身不可用时返回
// 错误；目标不可达不算。用于在批量扫描开始前发现配置错误的代理。
//
// 连接遵循 ctx 中的网络策略（见 HTTPClient.WithPolicy）：连接代理经过策略的 Dial；
// CheckTarget 拒绝 address 时只检查代理端口可以连接，不经代理访问该地址。
func CheckProxy(ctx context.Context, proxyURL, address string, timeout time.Duration) error {
	proxy, err := normalizeProxyURL(proxyURL)
	if err != nil || proxy == nil {
		return err
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	policy := PolicyFrom(ctx)
	// 先确认代理端口本身可以连接：SOCKS 的拨号错误不区分代理与目标。
	probe, err := policyDialer(policy.Dial, timeout, 0)(ctx, "tcp", proxy.Host)
	if err != nil {
		return &ProxyError{Proxy: proxy.Host, Err: fmt.Errorf("连接代理 %s 失败: %w", proxy.Host, err)}
	}
	_ = probe.Close()
	if checkTarget(ctx, policy, addressTarget(RequestTCP, "tcp", address, RequestInfoFrom(ctx))) != nil {
		return nil
	}
	conn, err := dialThroughProxy(ctx, "tcp", address, proxy, timeout, policy.Dial)
	if err == nil {
		_ = conn.Close()
		return nil
	}
	var proxyErr *ProxyError
	if errors.As(err, &proxyErr) {
		return proxyErr
	}
	return nil
}

// dialHTTPConnect 经 HTTP(S) 代理用 CONNECT 建立到目标的 TCP 隧道。
// 与 proxyclient v1.0.2 不同：拨号与 CONNECT 交互都受 ctx/超时约束，取消时立即中断；
// 代理返回非 2xx 时返回明确错误而非已关闭的连接；并保留响应后属于隧道的缓冲字节。
func dialHTTPConnect(ctx context.Context, network, address string, proxy *url.URL, timeout time.Duration, dial dialFunc) (net.Conn, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("HTTP(S) 代理不支持 %s（仅 TCP）", network)
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	if dial == nil {
		dial = policyDialer(nil, timeout, 0)
	}
	conn, err := dial(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, &ProxyError{Proxy: proxy.Host, Err: fmt.Errorf("连接 HTTP 代理失败: %w", err)}
	}
	// ctx 取消时关闭连接，让阻塞的握手读写立即返回。
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	fail := func(err error) (net.Conn, error) {
		stop()
		_ = conn.Close()
		return nil, err
	}
	// CONNECT 交互的截止时间取 ctx 截止时间与单次超时的较早者。
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if proxyUsesTLS(proxy) { // https 代理：先与代理完成 TLS（证书校验策略同 proxyTLSConfig）
		tlsConf, cfgErr := proxyTLSConfig(proxy)
		if cfgErr != nil {
			return fail(cfgErr)
		}
		tlsConn := tls.Client(conn, tlsConf)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return fail(&ProxyError{Proxy: proxy.Host, Err: fmt.Errorf("HTTP 代理 TLS 握手失败: %w", err)})
		}
		conn = tlsConn
	}

	var req strings.Builder
	req.WriteString("CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n")
	if proxy.User != nil {
		if user := proxy.User.Username(); user != "" {
			password, _ := proxy.User.Password()
			token := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
			req.WriteString("Proxy-Authorization: Basic " + token + "\r\n")
		}
	}
	req.WriteString("\r\n")
	if _, err = conn.Write([]byte(req.String())); err != nil {
		return fail(fmt.Errorf("发送 CONNECT 请求失败: %w", err))
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(fmt.Errorf("读取 CONNECT 响应失败: %w", err))
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(connectRejected(proxy.Host, resp))
	}
	if !stop() { // ctx 已在握手期间取消，连接可能已被关闭
		_ = conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{}) // 清除握手期截止时间，隧道生命周期由调用方管理
	if n := br.Buffered(); n > 0 {
		buffered := make([]byte, n)
		if _, err = io.ReadFull(br, buffered); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("读取隧道缓冲数据失败: %w", err)
		}
		return &prefixConn{Conn: conn, prefix: buffered}, nil
	}
	return conn, nil
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

func dialSOCKS5UDP(ctx context.Context, proxy *url.URL, target string, timeout time.Duration, dial dialFunc) (net.Conn, error) {
	host, port, err := splitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("解析 UDP 目标地址失败: %w", err)
	}
	var tlsConf *tls.Config
	if strings.HasSuffix(strings.ToLower(proxy.Scheme), "+tls") {
		if tlsConf, err = proxyTLSConfig(proxy); err != nil {
			return nil, err
		}
	}
	ctrl, err := dial(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 代理失败: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(deadline)
	} else if timeout > 0 {
		_ = ctrl.SetDeadline(time.Now().Add(timeout))
	}
	if tlsConf != nil {
		tlsConn := tls.Client(ctrl, tlsConf)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = ctrl.Close()
			return nil, fmt.Errorf("SOCKS5 代理 TLS 握手失败: %w", err)
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
	udpConn, err := dial(ctx, "udp", relayAddr)
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

// proxyUsesTLS 判断代理连接本身是否经 TLS（https 或 *+tls，如 socks5+tls）。
func proxyUsesTLS(proxy *url.URL) bool {
	if proxy == nil {
		return false
	}
	scheme := strings.ToLower(proxy.Scheme)
	return scheme == schemeHTTPS || strings.HasSuffix(scheme, "+tls")
}

// lowerProxyQuery 返回代理 URL 的查询参数，键统一转小写（参数名不区分大小写）。
func lowerProxyQuery(proxy *url.URL) url.Values {
	lowered := url.Values{}
	for key, values := range proxy.Query() {
		lowered[strings.ToLower(key)] = values
	}
	return lowered
}

// proxySkipVerify 判定是否跳过代理证书校验。默认跳过，与扫描目标的 TLS 策略一致
// （整个扫描器默认不校验证书）。显式 tls-insecure-skip-verify 优先（true=跳过，
// 其余=校验）；仅提供 tls-ca-file / tls-domain 时视为显式要求校验。
func proxySkipVerify(query url.Values) bool {
	if raw := query.Get("tls-insecure-skip-verify"); raw != "" {
		return strings.EqualFold(raw, "true")
	}
	return query.Get("tls-ca-file") == "" && query.Get("tls-domain") == ""
}

// applyProxyTLSDefaults 为经 TLS 的代理注入默认证书校验策略（默认跳过），使 proxyclient
// 的 TCP 路径与 gxx 自实现的 UDP 路径行为一致。非 TLS 代理（http/socks5/socks4）原样返回。
// 返回克隆，避免修改调用方持有的原始 URL。
func applyProxyTLSDefaults(proxy *url.URL) *url.URL {
	if !proxyUsesTLS(proxy) {
		return proxy
	}
	query := lowerProxyQuery(proxy)
	query.Set("tls-insecure-skip-verify", strconv.FormatBool(proxySkipVerify(query)))
	clone := *proxy
	clone.RawQuery = query.Encode()
	return &clone
}

// proxyTLSConfig 构造 socks5+tls 控制连接的 TLS 配置。默认跳过代理证书校验（与扫描
// 目标一致），查询参数与 proxyclient 的 TCP 路径相同：tls-insecure-skip-verify=false
// 显式开启校验，tls-domain 指定校验名，tls-ca-file 指定信任的 CA。参数名不区分大小写。
func proxyTLSConfig(proxy *url.URL) (*tls.Config, error) {
	query := lowerProxyQuery(proxy)
	conf := &tls.Config{
		ServerName:         query.Get("tls-domain"),
		InsecureSkipVerify: proxySkipVerify(query),
	}
	if conf.ServerName == "" {
		conf.ServerName = proxy.Hostname()
	}
	if caFile := query.Get("tls-ca-file"); caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("读取代理 CA 文件失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("代理 CA 文件没有可用证书: %s", caFile)
		}
		conf.RootCAs = pool
	}
	return conf, nil
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

// SetDeadline 等方法只作用于 UDP 中继连接；控制连接建立关联后不再读写，只负责维持关联。
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.relay.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }
