package network

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// selfSignedTLSServer 启动只允许指定套件的 TLS 1.2 服务器，用于验证客户端的套件兼容范围。
func selfSignedTLSServer(t *testing.T, key crypto.Signer, suites []uint16) *httptest.Server {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: suites,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestHTTPClientHandshakesWithAllSupportedCipherSuites(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		key    crypto.Signer
		suites []uint16
	}{
		// 现代 ECDSA 证书站点最常见的套件，曾因硬编码清单缺失而握手失败。
		{"ECDSA+AES128-GCM", ecdsaKey, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
		{"ECDSA+AES256-GCM", ecdsaKey, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}},
		{"ECDSA+CHACHA20", ecdsaKey, []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}},
		{"ECDHE-RSA+AES128-GCM", rsaKey, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}},
		// 扫描老旧设备所需的兼容套件，改用 Go 默认套件集会丢失它们。
		{"RSA密钥交换+AES128-CBC-SHA", rsaKey, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}},
		{"RSA密钥交换+AES128-GCM", rsaKey, []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}},
		{"ECDHE-RSA+AES128-CBC-SHA256", rsaKey, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := selfSignedTLSServer(t, tc.key, tc.suites)
			client := NewHTTPClient()
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := client.SendRequestHttp(ctx, http.MethodGet, server.URL, "", OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true})
			if err != nil {
				t.Fatalf("握手失败: %v", err)
			}
			defer resp.Body.Close()
			if body, _ := io.ReadAll(resp.Body); string(body) != "ok" {
				t.Fatalf("响应=%q", body)
			}
		})
	}
}

// 目标返回非 HTTP 报文时 retryablehttp 会触发 Raw TCP 回退。配置了代理后，回退必须同样走代理，
// 不能由库内部直接拨号目标而泄漏真实出口。
func TestProxyIsNeverBypassedByRawTCPFallback(t *testing.T) {
	var targetConns atomic.Int32
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			targetConns.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Read(make([]byte, 4096))
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			}(conn)
		}
	}()

	var tunnels atomic.Int32
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				upstream, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer upstream.Close()
				tunnels.Add(1)
				_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go func() { _, _ = io.Copy(upstream, reader) }()
				_, _ = io.Copy(conn, upstream)
			}(conn)
		}
	}()

	client := NewHTTPClient()
	defer client.Close()
	// 请求上下文很短：关闭回退后失败请求只会按重试策略退避，不必等满全部重试。
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	resp, _ := client.SendRequestHttp(ctx, http.MethodGet, "http://"+target.Addr().String()+"/", "",
		OptionsRequest{Proxy: "http://" + proxy.Addr().String(), Timeout: time.Second})
	if resp != nil {
		resp.Body.Close()
	}
	// 等待代理与目标两侧的计数稳定。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && targetConns.Load() != tunnels.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if tunnels.Load() == 0 {
		t.Fatal("请求没有经过代理")
	}
	if direct := targetConns.Load() - tunnels.Load(); direct != 0 {
		t.Fatalf("有 %d 个连接绕过代理直连目标（代理隧道=%d，目标连接=%d）", direct, tunnels.Load(), targetConns.Load())
	}
}

// 未配置代理时保持原有的兼容行为：非标准 HTTP 报文仍会被回退读取，而不是直接失败。
func TestRawTCPFallbackStillWorksWithoutProxy(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Read(make([]byte, 4096))
				_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			}(conn)
		}
	}()
	client := NewHTTPClient()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := client.SendRequestHttp(ctx, http.MethodGet, "http://"+target.Addr().String()+"/", "", OptionsRequest{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("无代理时应保留 Raw TCP 回退: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "SSH-2.0-OpenSSH") {
		t.Fatalf("回退响应=%q", body)
	}
}
