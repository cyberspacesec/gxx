package network

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// serverHelloMessage 按 RFC 5246/8446 的布局构造 ServerHello 握手消息。
func serverHelloMessage(version, cipher uint16, extensions []uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // 空会话标识
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0) // 不压缩
	var exts []byte
	for _, ext := range extensions {
		exts = binary.BigEndian.AppendUint16(exts, ext)
		exts = binary.BigEndian.AppendUint16(exts, 1)
		exts = append(exts, 0)
	}
	if extensions != nil {
		body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
		body = append(body, exts...)
	}
	return append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// JA3S 测试向量：字段与摘要按公开定义（SSLVersion,Cipher,SSLExtension 的十进制串取 MD5）
// 独立计算得出。
func TestJA3SVectors(t *testing.T) {
	cases := []struct {
		version, cipher uint16
		extensions      []uint16
		text, digest    string
	}{
		{0x0301, 0x002f, []uint16{65281, 0, 11, 35, 5, 16}, "769,47,65281-0-11-35-5-16", "836ce314215654b5b1f85f97c73e506f"},
		{0x0303, 0xc02f, []uint16{65281, 0, 11, 35, 16}, "771,49199,65281-0-11-35-16", "47decf033ac4c8fc9b952ff41e549679"},
		{0x0303, 0x1301, []uint16{43, 51}, "771,4865,43-51", ""},
		{0x0300, 0x0004, nil, "768,4,", ""},
	}
	for _, tc := range cases {
		hello, retry, err := ParseServerHello(serverHelloMessage(tc.version, tc.cipher, tc.extensions))
		if err != nil || retry {
			t.Fatalf("%s: %v retry=%v", tc.text, err, retry)
		}
		if hello.JA3SString() != tc.text {
			t.Fatalf("JA3S 字段 %q != %q", hello.JA3SString(), tc.text)
		}
		want := tc.digest
		if want == "" {
			sum := md5.Sum([]byte(tc.text))
			want = hex.EncodeToString(sum[:])
		}
		if hello.JA3S() != want {
			t.Fatalf("%s: %s != %s", tc.text, hello.JA3S(), want)
		}
	}
	if _, _, err := ParseServerHello([]byte{1, 0, 0, 0}); err == nil {
		t.Fatal("非 ServerHello 应报错")
	}
	truncated := serverHelloMessage(0x0303, 0xc02f, []uint16{1, 2})
	if _, _, err := ParseServerHello(truncated[:len(truncated)-3]); err == nil {
		t.Fatal("截断的消息应报错")
	}
}

// 记录层可以把 ServerHello 拆在多条记录里，也可以和后续握手消息挤在同一条记录里。
func TestHelloRecorderAcrossRecords(t *testing.T) {
	message := serverHelloMessage(0x0303, 0xc02f, []uint16{65281, 0, 23})
	message = append(message, 11, 0, 0, 1, 0) // 紧随其后的 Certificate 消息
	var stream []byte
	for _, part := range [][]byte{message[:7], message[7:]} {
		stream = append(stream, 22, 3, 3, byte(len(part)>>8), byte(len(part)))
		stream = append(stream, part...)
	}
	recorder := &helloRecorder{}
	for _, b := range stream {
		recorder.feed([]byte{b})
	}
	hello, found := recorder.serverHello()
	if !found || hello.JA3SString() != "771,49199,65281-0-23" || !recorder.done {
		t.Fatalf("found=%v hello=%+v done=%v", found, hello, recorder.done)
	}
}

// tapConn 记录服务端发往客户端的字节，供测试独立解析 ServerHello。
type tapListener struct {
	net.Listener
	mu       sync.Mutex
	captured [][]byte
}

type tapConn struct {
	net.Conn
	buf *[]byte
	mu  *sync.Mutex
}

func (l *tapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.captured = append(l.captured, nil)
	index := len(l.captured) - 1
	l.mu.Unlock()
	return &tapConn{Conn: conn, buf: &l.captured[index], mu: &l.mu}, nil
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	*c.buf = append(*c.buf, p...)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

// independentJA3S 只取第一条握手记录中的 ServerHello，按定义拼出 JA3S 字段串。
func independentJA3S(t *testing.T, stream []byte) string {
	t.Helper()
	if len(stream) < 5 || stream[0] != 22 {
		t.Fatalf("不是握手记录: % x", stream[:min(len(stream), 8)])
	}
	record := stream[5 : 5+int(binary.BigEndian.Uint16(stream[3:5]))]
	body := record[4 : 4+(int(record[1])<<16|int(record[2])<<8|int(record[3]))]
	version := binary.BigEndian.Uint16(body)
	at := 35 + int(body[34])
	cipher := binary.BigEndian.Uint16(body[at:])
	at += 3
	var exts []string
	if at < len(body) {
		end := at + 2 + int(binary.BigEndian.Uint16(body[at:]))
		for at += 2; at < end; {
			exts = append(exts, fmt.Sprint(binary.BigEndian.Uint16(body[at:])))
			at += 4 + int(binary.BigEndian.Uint16(body[at+2:]))
		}
	}
	return fmt.Sprintf("%d,%d,%s", version, cipher, strings.Join(exts, "-"))
}

// 同一次握手：JA3S 与独立抓取的服务端字节一致，版本与套件取自握手状态，证书照常
// 填入 resp.TLS；复用连接的第二个请求得到相同的摘要，不增加连接。扫描的 ClientHello
// 不携带 ALPN（与之前的版本一致），服务端即使支持也不会协商，ALPN 为空。
func TestResponseTLSFromExistingHandshake(t *testing.T) {
	for _, maxVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(maxVersion), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tap := &tapListener{Listener: ln}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
			server.Listener = tap
			server.TLS = &tls.Config{MaxVersion: maxVersion, NextProtos: []string{"http/1.1"}}
			server.StartTLS()
			defer server.Close()
			client := NewHTTPClient()
			defer client.Close()
			var infos []TLSInfo
			for i := 0; i < 2; i++ {
				resp, err := client.SendRequestHttp(context.Background(), http.MethodGet, server.URL+"/", "", OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true})
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				info, ok := ResponseTLS(resp)
				if !ok || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
					t.Fatalf("缺少握手信息: ok=%v tls=%v", ok, resp.TLS)
				}
				infos = append(infos, info)
			}
			tap.mu.Lock()
			captured := append([]byte(nil), tap.captured[0]...)
			connections := len(tap.captured)
			tap.mu.Unlock()
			sum := md5.Sum([]byte(independentJA3S(t, captured)))
			want := TLSInfo{Version: tls.VersionName(maxVersion), CipherSuite: infos[0].CipherSuite, JA3S: hex.EncodeToString(sum[:])}
			if infos[0] != want || infos[1] != want || connections != 1 || want.CipherSuite == "" {
				t.Fatalf("握手摘要=%+v / %+v，期望 %+v，连接数=%d", infos[0], infos[1], want, connections)
			}
		})
	}
}

// 响应头顺序按服务器发送的顺序记录，保留重复与原始大小写；1xx 中间响应不计入，
// 同一连接上的后续响应各自记录。
func TestResponseHeaderOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	responses := []string{
		"HTTP/1.1 100 Continue\r\nX-Interim: 1\r\n\r\nHTTP/1.1 200 OK\r\nX-Zeta: 1\r\nset-cookie: a=1\r\nAlpha: 2\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 404 Not Found\r\nServer: demo\r\nContent-Length: 0\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n",
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for _, response := range responses {
			if _, err := http.ReadRequest(reader); err != nil {
				return
			}
			_, _ = io.WriteString(conn, response)
		}
		_, _ = io.Copy(io.Discard, reader)
	}()
	client := NewHTTPClient()
	defer client.Close()
	want := [][]string{{"X-Zeta", "set-cookie", "Alpha", "Set-Cookie", "Content-Length"}, {"Server", "Content-Length", "Date"}}
	for i := range responses {
		resp, err := client.SendRequestHttp(context.Background(), http.MethodGet, "http://"+ln.Addr().String()+"/", "", OptionsRequest{Timeout: 3 * time.Second, FollowRedirects: true})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if got := ResponseHeaderOrder(resp); !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("第 %d 个响应的顺序 %q != %q", i+1, got, want[i])
		}
	}
}
