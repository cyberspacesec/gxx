package network

import (
	"context"
	"net"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

// 一个资产由协议、主机和端口共同确定：http://a.com、https://a.com 与
// http://a.com:8080 是三个不同的资产。扫描请求不会离开它所属的资产。

// Origin 返回 URL 的规范化源 "scheme://host:port"：协议与主机小写，
// 省略的端口按协议补全。不是 http/https 或缺少主机时返回空串。
func Origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || scheme != "http" && scheme != "https" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + ":" + port
}

// SameOrigin 报告两个 URL 是否属于同一资产。
func SameOrigin(a, b *url.URL) bool {
	origin := Origin(a)
	return origin != "" && origin == Origin(b)
}

// SameSite 报告两个 http/https 地址是否属于同一站点：主机相同，或两者都是域名且
// 可注册域（eTLD+1）相同。站点不区分协议与端口，用于附属资源的跳转判断。
func SameSite(a, b *url.URL) bool {
	if a == nil || b == nil || Origin(a) == "" || Origin(b) == "" {
		return false
	}
	hostA := strings.ToLower(strings.TrimSuffix(a.Hostname(), "."))
	hostB := strings.ToLower(strings.TrimSuffix(b.Hostname(), "."))
	if hostA == hostB {
		return true
	}
	if net.ParseIP(hostA) != nil || net.ParseIP(hostB) != nil {
		return false
	}
	siteA, errA := publicsuffix.EffectiveTLDPlusOne(hostA)
	siteB, errB := publicsuffix.EffectiveTLDPlusOne(hostB)
	return errA == nil && errB == nil && siteA == siteB
}

// TargetCandidates 返回目标可能对应的完整地址，按尝试顺序排列。
// 已带协议的目标只有它自身；未带协议时端口 80 只尝试 http，端口 443 只尝试
// https，其余先 https 后 http。samePort 表示各候选连接的是同一个 TCP 端口，
// 此时连接失败无需再尝试另一个协议。
func TargetCandidates(target string) (candidates []string, samePort bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, false
	}
	if i := strings.Index(target, "://"); i >= 0 {
		return []string{target}, true
	}
	u, err := url.Parse(HttpPrefix + target)
	if err != nil || u.Host == "" {
		return []string{HttpsPrefix + target}, true
	}
	switch u.Port() {
	case "80":
		return []string{HttpPrefix + target}, true
	case "443":
		return []string{HttpsPrefix + target}, true
	case "":
		return []string{HttpsPrefix + target, HttpPrefix + target}, false
	}
	return []string{HttpsPrefix + target, HttpPrefix + target}, true
}

// WithConnectProbe 跟踪 ctx 下的请求是否建立过 TCP 连接。
//
// 目标未写协议且带端口时，https 与 http 连接的是同一个端口：TCP 连接失败说明
// 端口不可达，换协议只会再等一次超时；连接成功而握手或读取失败才值得改用 http。
// 经代理时连接的是代理，探针恒为已连接，调用方会照常尝试两种协议。
func WithConnectProbe(ctx context.Context) (context.Context, func() bool) {
	var connected atomic.Bool
	trace := &httptrace.ClientTrace{
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				connected.Store(true)
			}
		},
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	}
	return httptrace.WithClientTrace(ctx, trace), connected.Load
}
