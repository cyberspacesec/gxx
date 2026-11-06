package network

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newProxyTLSCert 生成 127.0.0.1 的自签证书，返回用于监听的证书与可作信任根的 CA 文件。
func newProxyTLSCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gxx-test-proxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caFile
}

// startSOCKS5TLSProxy 启动一个控制连接经 TLS 的 SOCKS5 代理（支持 CONNECT 与 UDP ASSOCIATE）。
func startSOCKS5TLSProxy(t *testing.T, cert tls.Certificate) *socks5TestProxy {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = ln.Close() })
	p := &socks5TestProxy{addr: raw.Addr().String(), tcpAssociates: &int32Counter{}, udpAssociates: &int32Counter{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(t, c)
		}
	}()
	return p
}

// startHTTPSConnectProxy 启动一个本体经 TLS 的 HTTPS CONNECT 代理，隧道转发到固定后端。
func startHTTPSConnectProxy(t *testing.T, cert tls.Certificate, backend string) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := net.Dial("tcp", backend)
				if err != nil {
					_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
					return
				}
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return "https://" + raw.Addr().String()
}

// TestSOCKS5TLSUDPProxyCertDefaultsToSkip 验证 UDP 经 socks5+tls 默认跳过代理证书校验，
// 并可通过查询参数显式开启校验或提供自定义 CA。
func TestSOCKS5TLSUDPProxyCertDefaultsToSkip(t *testing.T) {
	cert, caFile := newProxyTLSCert(t)
	p := startSOCKS5TLSProxy(t, cert)
	target := udpEchoServer(t)
	base := "socks5+tls://" + p.addr

	// 默认：不校验，自签证书也能建连。
	if got, err := dialAndEcho(t, "udp", target, base, "hello"); err != nil || got != "echo:hello" {
		t.Fatalf("默认应跳过代理证书校验：回显=%q err=%v", got, err)
	}
	// 显式开启校验：自签证书应被拒绝。
	if _, err := dialAndEcho(t, "udp", target, base+"?tls-insecure-skip-verify=false", "hello"); err == nil {
		t.Fatal("显式校验时自签代理证书应被拒绝")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("期望证书校验错误，得到: %v", err)
	}
	// 提供受信任 CA：校验通过。
	if got, err := dialAndEcho(t, "udp", target, base+"?tls-ca-file="+url.QueryEscape(caFile), "hello"); err != nil || got != "echo:hello" {
		t.Fatalf("提供受信任 CA 时应校验通过：回显=%q err=%v", got, err)
	}
	// CA 文件不存在：明确报错。
	missing := url.QueryEscape(filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := dialAndEcho(t, "udp", target, base+"?tls-ca-file="+missing, "x"); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("CA 文件不存在应明确报错: %v", err)
	}
}

// TestSOCKS5TLSTCPProxyCertDefaultsToSkip 验证 TCP 经 socks5+tls 与 UDP 行为一致：
// 默认跳过代理证书校验，显式开启校验时自签证书失败。
func TestSOCKS5TLSTCPProxyCertDefaultsToSkip(t *testing.T) {
	cert, _ := newProxyTLSCert(t)
	p := startSOCKS5TLSProxy(t, cert)
	target := tcpEchoServer(t)
	base := "socks5+tls://" + p.addr

	if got, err := dialAndEcho(t, "tcp", target, base, "ping"); err != nil || got != "ping" {
		t.Fatalf("默认应跳过代理证书校验：回显=%q err=%v", got, err)
	}
	if _, err := dialAndEcho(t, "tcp", target, base+"?tls-insecure-skip-verify=false", "ping"); err == nil {
		t.Fatal("显式校验时自签代理证书应被拒绝")
	}
}

// TestHTTPSProxyCertDefaultsToSkip 验证 HTTP 客户端经 https 代理默认跳过代理证书校验，
// 显式开启校验时自签证书失败。
func TestHTTPSProxyCertDefaultsToSkip(t *testing.T) {
	cert, _ := newProxyTLSCert(t)
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "backend-ok")
	}))
	defer backend.Close()
	proxyURL := startHTTPSConnectProxy(t, cert, backend.Listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewHTTPClient()
	defer client.Close()
	resp, err := client.SendRequestHttp(ctx, "GET", backend.URL+"/", "", OptionsRequest{Proxy: proxyURL, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("默认应跳过 https 代理证书校验: %v", err)
	}
	resp.Body.Close()
	if hits.Load() == 0 {
		t.Fatal("后端未经代理被访问")
	}

	verify := NewHTTPClient()
	defer verify.Close()
	if _, err := verify.SendRequestHttp(ctx, "GET", backend.URL+"/", "", OptionsRequest{Proxy: proxyURL + "?tls-insecure-skip-verify=false", Timeout: 3 * time.Second}); err == nil {
		t.Fatal("显式校验时自签 https 代理证书应握手失败")
	}
}
