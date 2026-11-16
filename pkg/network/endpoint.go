package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Endpoint 是 TCP/UDP 连接地址解析后的拨号端点。
type Endpoint struct {
	Host string // 主机名或 IP 字面量；IPv6 不带方括号，zone 以 % 分隔
	Port string
	TLS  bool // 是否在连接上进行 TLS 握手；UDP 恒为 false
}

// Address 返回可直接拨号的 host:port，IPv6 自动加方括号。
func (e Endpoint) Address() string { return net.JoinHostPort(e.Host, e.Port) }

// ParseEndpoint 是 TCP/UDP 连接地址的唯一解析入口，同时决定主机、端口与是否握手，
// 使拨号地址、TLS 与 ServerName 不会由多处各自推断而互相矛盾。
//
// 地址形式：
//
//	host            host:port            [host]:port
//	scheme://host   scheme://host:port   scheme://[host]:port/path
//
// scheme 可为 tcp、udp、http（明文）或 https、tls、ssl（TLS）。带 scheme 的地址
// 允许携带用户信息、路径与查询（规则未写 host 时直接使用扫描目标 URL），解析时
// 只取主机和端口；不带 scheme 的地址只能是主机和端口。
//
// 方括号用于界定主机：IPv6 字面量必须加方括号，域名与 IPv4 也可以加，
// 因此 "[{{domain}}]:22" 对任何目标都没有歧义。未加方括号且含多个冒号的地址
// 无法区分地址与端口（"2001:db8::1:80" 有两种读法），一律拒绝。
//
// TLS 与缺省端口：https/tls/ssl 握手、缺省 443；http/tcp/udp 明文、缺省 80；
// 不带 scheme 时端口 443 或未写端口视为 TLS（缺省 443），其余端口明文。
// UDP 没有 TLS 通道，network 为 UDP 时从不握手，未写端口且无 scheme 时取 80。
func ParseEndpoint(address, network string) (Endpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return Endpoint{}, errors.New("连接地址为空")
	}
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = DefaultNetwork
	}
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return Endpoint{}, fmt.Errorf("不支持的网络类型 %q", network)
	}

	scheme, authority := "", address
	if index := strings.Index(address, "://"); index >= 0 {
		scheme, authority = strings.ToLower(address[:index]), address[index+len("://"):]
		switch scheme {
		case "tcp", "udp", "http", "https", "tls", "ssl":
		default:
			return Endpoint{}, fmt.Errorf("不支持的连接协议 %q", scheme)
		}
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			authority = authority[:end]
		}
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			authority = authority[at+1:]
		}
	} else if strings.ContainsAny(authority, "/?#@") {
		return Endpoint{}, fmt.Errorf("连接地址 %q 只能包含主机和端口", address)
	}

	host, port, err := splitAuthority(authority)
	if err != nil {
		return Endpoint{}, fmt.Errorf("连接地址无效 %q: %w", address, err)
	}
	secure := false
	switch scheme {
	case "https", "tls", "ssl":
		secure = true
	case "":
		secure = port == "443" || port == ""
	}
	if isUDPNetwork(network) {
		secure = false
	}
	if port == "" {
		port = "80"
		if secure || scheme == "https" || scheme == "tls" || scheme == "ssl" {
			port = "443"
		}
	}
	return Endpoint{Host: host, Port: port, TLS: secure}, nil
}

// splitAuthority 把 "host"、"host:port"、"[host]"、"[host]:port" 拆成主机与端口。
func splitAuthority(authority string) (host, port string, err error) {
	hasPort := false
	switch {
	case strings.HasPrefix(authority, "["):
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", "", errors.New("方括号未闭合")
		}
		host = authority[1:end]
		if rest := authority[end+1:]; rest != "" {
			if rest[0] != ':' {
				return "", "", errors.New("方括号之后只能是端口")
			}
			port, hasPort = rest[1:], true
		}
		if strings.Contains(host, ":") {
			if host, err = normalizeIPv6(host); err != nil {
				return "", "", err
			}
		} else if err = validateHostname(host); err != nil {
			return "", "", err
		}
	case strings.Count(authority, ":") > 1:
		return "", "", errors.New("IPv6 字面量需加方括号（如 [2001:db8::1]:80）")
	default:
		host, port, hasPort = strings.Cut(authority, ":")
		if err = validateHostname(host); err != nil {
			return "", "", err
		}
	}
	if hasPort {
		if number, convErr := strconv.ParseUint(port, 10, 16); convErr != nil || number == 0 {
			return "", "", fmt.Errorf("端口无效: %q", port)
		}
	}
	return host, port, nil
}

// normalizeIPv6 校验方括号内的 IPv6 字面量。zone 可写成 URL 形式的 %25eth0
// 或拨号形式的 %eth0，统一返回后者。
func normalizeIPv6(literal string) (string, error) {
	address, zone, zoned := strings.Cut(literal, "%")
	if zoned {
		if encoded, ok := strings.CutPrefix(zone, "25"); ok && encoded != "" {
			zone = encoded
		}
		if zone == "" {
			return "", errors.New("IPv6 zone 为空")
		}
		literal = address + "%" + zone
	}
	if parsed, err := netip.ParseAddr(literal); err != nil || !parsed.Is6() {
		return "", errors.New("方括号内不是合法的 IPv6 字面量")
	}
	return literal, nil
}

// validateHostname 约束域名或 IPv4：不能为空，不能含分隔符、空白或控制字符。
func validateHostname(host string) error {
	if host == "" {
		return errors.New("缺少主机")
	}
	for i := 0; i < len(host); i++ {
		switch c := host[i]; {
		case c <= ' ' || c == 0x7f:
			return errors.New("主机包含空白或控制字符")
		case strings.IndexByte("[]%\\/?#@", c) >= 0:
			return fmt.Errorf("主机包含非法字符 %q", c)
		}
	}
	return nil
}
