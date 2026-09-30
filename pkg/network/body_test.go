package network

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestReadResponseBodyPreservesBoundsAndLengthHints(t *testing.T) {
	for _, length := range []int64{-1, 0, 2, 100, 1 << 40} {
		for _, limit := range []int64{0, 3, 8, 20} {
			resp := &http.Response{Body: io.NopCloser(strings.NewReader("abcdefgh")), ContentLength: length}
			got, err := ReadResponseBody(resp, limit)
			want := []byte("abcdefgh")[:min(limit, 8)]
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("length=%d limit=%d got=%q err=%v", length, limit, got, err)
			}
		}
	}
	short, err := ReadResponseBody(&http.Response{Body: io.NopCloser(strings.NewReader("short")), ContentLength: 1 << 40}, 512<<10)
	if err != nil || cap(short) > 8192 {
		t.Fatalf("夸大长度导致过度预分配: cap=%d err=%v", cap(short), err)
	}
}

type fragmentedBody struct {
	data []byte
	err  error
}

func (r *fragmentedBody) Read(p []byte) (int, error) {
	n := min(len(p), len(r.data), 997)
	copy(p, r.data[:n])
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}
func (*fragmentedBody) Close() error { return nil }

func TestSegmentedResponseMatchesLimitedReadAll(t *testing.T) {
	for _, size := range []int{0, 511, 512, 513, 4096, 32769, 262144, 600000} {
		data := bytes.Repeat([]byte("0123456789abcdef"), (size+15)/16)[:size]
		for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF} {
			for _, limit := range []int64{0, 513, 32768, 512 << 10, 1 << 20} {
				want, wantErr := io.ReadAll(io.LimitReader(&fragmentedBody{data, terminal}, limit))
				for _, length := range []int64{-1, int64(size), int64(size / 2), 1 << 40} {
					reader := &fragmentedBody{data, terminal}
					got, err := ReadResponseBody(&http.Response{Body: reader, ContentLength: length}, limit)
					if !bytes.Equal(got, want) || err != wantErr || int64(size-len(reader.data)) > limit {
						t.Fatalf("size=%d length=%d limit=%d len=%d err=%v wantErr=%v", size, length, limit, len(got), err, wantErr)
					}
				}
			}
		}
	}
}

func TestSegmentedResponsesOwnTheirData(t *testing.T) {
	var wg sync.WaitGroup
	retained := make([][]byte, 64)
	for i := range retained {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte(i)}, 100000+i)
			for j := 0; j < 3; j++ {
				got, err := ReadResponseBody(&http.Response{Body: io.NopCloser(bytes.NewReader(want)), ContentLength: -1}, MaxDefaultBody)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("并发响应数据损坏: i=%d err=%v", i, err)
				}
				if j == 0 {
					retained[i] = got
				}
			}
		}(i)
	}
	wg.Wait()
	for i, got := range retained {
		if !bytes.Equal(got, bytes.Repeat([]byte{byte(i)}, 100000+i)) {
			t.Fatalf("暂存区复用覆盖已返回数据: i=%d", i)
		}
	}
}

type failedBody struct{ err error }

func (r failedBody) Read(p []byte) (int, error) { return copy(p, "short"), r.err }
func (r failedBody) Close() error               { return nil }

func TestReadResponseBodyPropagatesReadErrors(t *testing.T) {
	failure := errors.New("传输中断")
	for _, length := range []int64{-1, 50} {
		got, err := ReadResponseBody(&http.Response{Body: failedBody{failure}, ContentLength: length}, 1024)
		if !errors.Is(err, failure) || string(got) != "short" {
			t.Fatalf("length=%d data=%q err=%v", length, got, err)
		}
	}
}
