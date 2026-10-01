package finger

import (
	"bytes"
	"context"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/common"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gproto "google.golang.org/protobuf/proto"
)

func TestOwnedResponsePreservesEncodingAndRawFields(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("ASCII"), []byte("中文 ſ Σ"), {0xc4, 0xe3, 0xba, 0xc3}, {0xff, 0, 0xfe}} {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/page", nil)
		resp := &http.Response{Request: req, StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/plain"}}}
		ctx := context.Background()
		want := buildProtoResponseBody(ctx, resp, []byte(common.Str2UTF8(string(data))), 123, nil, network.OptionsRequest{})
		got := BuildProtoResponseOwned(ctx, resp, bytes.Clone(data), 123, nil, network.OptionsRequest{})
		if !gproto.Equal(got, want) {
			t.Fatalf("编码或响应字段变化: data=%x got=%v want=%v", data, got, want)
		}
		raw := bytes.Clone(got.Raw)
		clear(got.Body)
		if !bytes.Equal(raw, got.Raw) {
			t.Fatal("正文与完整报文共用可变数组")
		}
	}
}

func TestShortNonImageFaviconDoesNotPanic(t *testing.T) {
	for size := 0; size < 8; size++ {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(strings.Repeat("x", size)))
		}))
		client := network.NewHTTPClient()
		got := NewGetIconHash(s.URL, "").WithHTTPClient(client).Run(context.Background())
		client.Close()
		s.Close()
		if got != "0" {
			t.Fatalf("短非图片正文被识别为图标: size=%d hash=%s", size, got)
		}
	}
}
