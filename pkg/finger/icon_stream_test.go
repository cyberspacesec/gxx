package finger

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/network"
)

type iconFragmentReader struct {
	data []byte
	step int
	err  error
}

func (r *iconFragmentReader) Read(p []byte) (int, error) {
	n := min(len(p), len(r.data), r.step)
	copy(p, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestStreamIconHashPreservesAllEncodingBoundaries(t *testing.T) {
	data := bytes.Repeat([]byte("\x89PNG\r\n\x1a\n0123456789abcdef"), 44000)
	lengths := make([]int, 4097)
	for i := range lengths {
		lengths[i] = i
	}
	lengths = append(lengths, 65535, 524288, 1048576, len(data))
	for _, size := range lengths {
		want := hashIconBytes(data[:size])
		for _, step := range []int{7, 57, 1824, 4096} {
			got, err := hashIconReader(&iconFragmentReader{data[:size], step, io.EOF}, nil)
			if err != nil || got != want {
				t.Fatalf("Reader 分块改变哈希: size=%d step=%d got=%d want=%d err=%v", size, step, got, want, err)
			}
		}
	}
	for _, err := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded, errors.New("broken stream")} {
		if hash, gotErr := hashIconReader(&iconFragmentReader{data[:4096], 7, err}, nil); hash != 0 || gotErr != err {
			t.Fatalf("读取失败产生了前缀哈希: hash=%d err=%v", hash, gotErr)
		}
	}
}

func TestLargeIconReadsCompleteKnownAndChunkedBodies(t *testing.T) {
	data := bytes.Repeat([]byte("complete image data"), ((16<<20)/19)+1)
	want := hashIconBytes(data)
	for _, chunked := range []bool{false, true} {
		t.Run(strconv.FormatBool(chunked), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "image/png")
				if chunked {
					w.(http.Flusher).Flush()
				} else {
					w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				}
				w.Write(data)
			}))
			defer s.Close()
			client := network.NewHTTPClient()
			defer client.Close()
			if got := NewGetIconHash(s.URL, "").WithHTTPClient(client).WithTimeout(5*time.Second).hashHTTPURL(context.Background(), s.URL); got != want {
				t.Fatalf("大图标未完整计算: chunked=%v got=%d want=%d", chunked, got, want)
			}
		})
	}
}

func TestLargeInlineIconUsesCompleteDecodedPayload(t *testing.T) {
	data := bytes.Repeat([]byte("inline image data"), ((4<<20)/17)+1)
	want := hashIconBytes(data)
	for _, payload := range []string{base64.StdEncoding.EncodeToString(data), base64.RawStdEncoding.EncodeToString(data)} {
		if got := (&GetIconHash{}).hashDataURL("data:image/png;base64," + payload); got != want {
			t.Fatalf("大内联图标哈希不完整: got=%d want=%d", got, want)
		}
	}
	for _, invalid := range []string{"YW=", "YWJj=", "YWJj%", "%GG", "YWJj!"} {
		if got := (&GetIconHash{}).hashDataURL("data:image/png;base64," + invalid); got != 0 {
			t.Fatalf("无效 Base64/转义产生哈希: %q => %d", invalid, got)
		}
	}
}

func TestIconProbeHandlesLargePreambleAndChunkBoundaries(t *testing.T) {
	for _, first := range []string{"svg", "html", "head", "body", "error"} {
		data := []byte("\xef\xbb\xbf<?xml version='1.0'?><!--" + strings.Repeat("comment-", 100000) + "--><" + first + "></" + first + ">")
		for _, step := range []int{1, 57, 1824, 65536} {
			var probe iconContentProbe
			hash, err := hashIconReader(&iconFragmentReader{data, step, io.EOF}, &probe)
			probe.finish()
			if err != nil || hash != hashIconBytes(data) || (first != "error" && !probe.elementIs(first)) || probe.html() != (first == "html" || first == "head" || first == "body") {
				t.Fatalf("流式文件识别错误: first=%s step=%d nameLength=%d err=%v", first, step, probe.nameN, err)
			}
		}
	}
}

func TestIncompleteHTTPIconNeverHashesPrefix(t *testing.T) {
	for _, slow := range []bool{false, true} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "100000")
			fmt.Fprint(w, "partial image")
			w.(http.Flusher).Flush()
			if slow {
				<-r.Context().Done()
			}
		}))
		client := network.NewHTTPClient()
		got := NewGetIconHash(s.URL, "").WithHTTPClient(client).WithTimeout(50*time.Millisecond).hashHTTPURL(context.Background(), s.URL)
		client.Close()
		s.Close()
		if got != 0 {
			t.Fatalf("提前断流或超时产生前缀哈希: slow=%v hash=%d", slow, got)
		}
	}
}

func TestLargeHTMLErrorIsRejectedBeforeReadingWholeResource(t *testing.T) {
	data := []byte("<!doctype html><html><body>" + strings.Repeat("error page", 1<<20))
	for _, imageMIME := range []bool{false, true} {
		reader := bytes.NewReader(data)
		probe := iconContentProbe{validate: true, imageMIME: imageMIME}
		hash, err := hashIconReader(reader, &probe)
		if hash != 0 || !errors.Is(err, errNotIcon) || reader.Len() == 0 {
			t.Fatalf("HTML 错误页被全量读取或作为图标: imageMIME=%v hash=%d remaining=%d err=%v", imageMIME, hash, reader.Len(), err)
		}
	}
	data = []byte("<?xml version='1.0'?><!--" + strings.Repeat("comment ", 100000) + "--><svg></svg>")
	reader := bytes.NewReader(data)
	probe := iconContentProbe{validate: true}
	got, err := hashIconReader(reader, &probe)
	if err != nil || got != hashIconBytes(data) || reader.Len() != 0 {
		t.Fatalf("有长前导的 SVG 未读取到 EOF: hash=%d remaining=%d err=%v", got, reader.Len(), err)
	}
}

func BenchmarkCompleteIconStream(b *testing.B) {
	for _, size := range []int{4096, 4 << 20, 16 << 20} {
		data := bytes.Repeat([]byte("x"), size)
		b.Run(strconv.Itoa(size)+"/Stream", func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = hashIconReader(bytes.NewReader(data), nil)
			}
		})
		b.Run(strconv.Itoa(size)+"/ReadAll", func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				body, err := io.ReadAll(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				_ = hashIconBytes(body)
			}
		})
		svg := []byte("<svg>" + strings.Repeat(" ", size) + "</svg>")
		b.Run(strconv.Itoa(size)+"/SVG", func(b *testing.B) {
			b.SetBytes(int64(len(svg)))
			b.ReportAllocs()
			for b.Loop() {
				probe := iconContentProbe{validate: true}
				_, _ = hashIconReader(bytes.NewReader(svg), &probe)
			}
		})
	}
}
