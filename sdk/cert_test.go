package sdk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

// tlsFixture 用一张字段齐全的自签证书启动 HTTPS 服务。
func tlsFixture(t *testing.T) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffe, _ := url.Parse("spiffe://gxx.test/service")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(424242),
		Subject: pkix.Name{
			CommonName: "gxx.test", Organization: []string{"GXX Org"}, OrganizationalUnit: []string{"Scan"},
			Country: []string{"CN"}, Province: []string{"Zhejiang"}, Locality: []string{"Hangzhou"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"gxx.test", "www.gxx.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses:        []string{"ops@gxx.test"},
		URIs:                  []*url.URL{spiffe},
		OCSPServer:            []string{"http://ocsp.gxx.test"},
		IssuingCertificateURL: []string{"http://ca.gxx.test/ca.crt"},
		CRLDistributionPoints: []string{"http://crl.gxx.test/ca.crl"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>tls fixture</title></head><body>ok</body></html>")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, cert
}

// TestCertificateExtraction 锁定 HTTPS 目标的证书提取：Scan、GetBaseInfo 与
// 内部结构输出的字段一致，SAN 中的 URI 与签发者地址不丢失。
func TestCertificateExtraction(t *testing.T) {
	server, want := tlsFixture(t)
	e := engine(t, "id: tlsprobe\ninfo:\n  name: tlsprobe\nrules:\n  r0:\n    request:\n      path: /\n    expression: response.status == 200\nexpression: r0()\n")

	check := func(t *testing.T, certs []sdk.CertInfo) {
		t.Helper()
		if len(certs) != 1 {
			t.Fatalf("证书数量=%d, want 1", len(certs))
		}
		c := certs[0]
		spki := sha1.Sum(want.RawSubjectPublicKeyInfo)
		checks := []struct {
			name      string
			got, want any
		}{
			{"CN", c.Subject.CommonName, "gxx.test"},
			{"O", c.Subject.Organization, []string{"GXX Org"}},
			{"OU", c.Subject.OrganizationalUnit, []string{"Scan"}},
			{"C", c.Subject.Country, []string{"CN"}},
			{"ST", c.Subject.Province, []string{"Zhejiang"}},
			{"L", c.Subject.Locality, []string{"Hangzhou"}},
			{"issuer CN", c.Issuer.CommonName, "gxx.test"},
			{"serial", c.SerialNumber, "424242"},
			{"valid", c.Valid, true},
			{"version", c.Version, 3},
			{"public key alg", c.PublicKeyAlgorithm, "ECDSA"},
			{"signature alg", c.SignatureAlgorithm, "ECDSA-SHA256"},
			{"spki sha1", c.PublicKey, strings.ToUpper(hex.EncodeToString(spki[:]))},
			{"not before", c.NotBefore, want.NotBefore.UTC().Format("2006-01-02 15:04:05")},
			{"not after", c.NotAfter, want.NotAfter.UTC().Format("2006-01-02 15:04:05")},
			{"dns", c.DNSNames, []string{"gxx.test", "www.gxx.test"}},
			{"ip", c.IPAddresses, []string{"127.0.0.1"}},
			{"email", c.EmailAddresses, []string{"ops@gxx.test"}},
			{"uri", c.URIs, []string{"spiffe://gxx.test/service"}},
			{"ocsp", c.OCSPServer, []string{"http://ocsp.gxx.test"}},
			{"issuing url", c.IssuingCertificateURL, []string{"http://ca.gxx.test/ca.crt"}},
			{"crl", c.CRLDistributionPoints, []string{"http://crl.gxx.test/ca.crl"}},
		}
		for _, item := range checks {
			if fmt.Sprint(item.got) != fmt.Sprint(item.want) {
				t.Errorf("%s = %v, want %v", item.name, item.got, item.want)
			}
		}
	}

	t.Run("scan", func(t *testing.T) {
		result, err := e.Scan(context.Background(), server.URL)
		if err != nil {
			t.Fatal(err)
		}
		check(t, result.Certs)
	})
	t.Run("base info", func(t *testing.T) {
		info, err := e.GetBaseInfo(context.Background(), server.URL)
		if err != nil {
			t.Fatal(err)
		}
		check(t, info.Certs)
	})
	t.Run("plain http has no certs", func(t *testing.T) {
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
		defer plain.Close()
		result, err := e.Scan(context.Background(), plain.URL)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Certs) != 0 {
			t.Fatalf("明文 HTTP 不应有证书: %+v", result.Certs)
		}
	})
}
