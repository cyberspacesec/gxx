package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/v2/pkg/network"
)

func TestHTTPClient_CheckProtocol_HTTPOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()

	got, err := client.CheckProtocol(context.Background(), host, "", 5*time.Second)
	if err != nil {
		t.Fatalf("CheckProtocol: %v", err)
	}
	if got != network.HttpPrefix+host {
		t.Fatalf("got %q, want http://%s", got, host)
	}
}

func TestHTTPClient_CheckProtocol_HTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()

	got, err := client.CheckProtocol(context.Background(), host, "", 5*time.Second)
	if err != nil {
		t.Fatalf("CheckProtocol: %v", err)
	}
	if got != network.HttpsPrefix+host {
		t.Fatalf("got %q, want https://%s", got, host)
	}
}

func TestHTTPClient_CheckProtocol_RespectsTimeoutAndContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	client := network.NewHTTPClient()
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := client.CheckProtocol(ctx, host, "", 200*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout or context error")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("expected probe to respect ~200ms timeout, took %v", elapsed)
	}
}
