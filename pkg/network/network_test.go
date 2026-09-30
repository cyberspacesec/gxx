package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRawHTTPResponseAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Length", "4")
		if r.Method != http.MethodHead {
			fmt.Fprint(w, "pong")
		}
	}))
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	opts := OptionsRequest{Timeout: time.Second, InsecureSkipVerify: true}
	for _, method := range []string{"GET", "HEAD"} {
		resp, err := client.SendRawRequest(context.Background(), method+" / HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, opts)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || method == "GET" && string(data) != "pong" || method == "HEAD" && len(data) != 0 {
			t.Fatalf("%s: status=%d body=%q err=%v", method, resp.StatusCode, data, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.SendRawRequest(ctx, "GET /wait HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, opts)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("取消未中断 Raw HTTP: %v", err)
	}
}

func TestRawHTTPBufferedBodyCannotSucceedAfterCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4")
		fmt.Fprint(w, "pong")
		w.(http.Flusher).Flush()
	}))
	defer server.Close()
	client := NewHTTPClient()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := client.SendRawRequest(ctx, "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n", server.URL, OptionsRequest{Timeout: time.Second, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	cancel()
	if body, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后缓冲正文仍被视为成功: body=%q err=%v", body, err)
	}
}

func TestTCPAndUDPResponses(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			var address string
			if protocol == "tcp" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				address = listener.Addr().String()
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					buffer := make([]byte, 16)
					if _, err := conn.Read(buffer); err == nil {
						conn.Write([]byte("pong"))
					}
				}()
			} else {
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				address = conn.LocalAddr().String()
				go func() {
					buffer := make([]byte, 16)
					_, peer, err := conn.ReadFrom(buffer)
					if err == nil {
						conn.WriteTo([]byte("pong"), peer)
					}
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, err := NewClientContext(ctx, address, TcpOrUdpConfig{Network: protocol, MaxRetries: 1, ReadTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Send([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			got, err := client.Receive()
			if err != nil || string(got) != "pong" {
				t.Fatalf("响应=%q err=%v", got, err)
			}
		})
	}
}
