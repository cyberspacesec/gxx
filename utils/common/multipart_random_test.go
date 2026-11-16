package common

import (
	"strings"
	"sync"
	"testing"
)

func TestDealMultipart(t *testing.T) {
	body := "------B\nContent-Disposition: form-data; name=\"a\"\n\nvalue\n------B\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\nContent-Type: text/plain\n\nline1\n\nline3\n------B--\n"
	want := "------B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue\r\n" +
		"------B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nline1\n\nline3\r\n" +
		"------B--\r\n"
	for _, contentType := range []string{
		"multipart/form-data; boundary=----B",
		"Multipart/Form-Data; BOUNDARY=----B",
		`multipart/form-data; boundary="----B"`,
		"multipart/form-data; charset=utf-8; boundary=----B",
		"multipart/form-data;boundary=----B; foo=bar",
	} {
		got, err := DealMultipart(contentType, body)
		if err != nil {
			t.Fatalf("%q: %v", contentType, err)
		}
		if got != want {
			t.Fatalf("%q:\ngot  %q\nwant %q", contentType, got, want)
		}
	}
	if _, err := DealMultipart("application/json", body); err == nil {
		t.Fatal("非 multipart 应返回错误")
	}
}

func TestRandomStrings(t *testing.T) {
	if RandomString(0) != "" || RandomString(-1) != "" || RandLetters(-3) != "" {
		t.Fatal("非正长度应返回空串")
	}
	if s := RandLetters(32); len(s) != 32 || strings.Trim(s, letterBytes) != "" {
		t.Fatalf("RandLetters=%q", s)
	}
	if s := RandomString(32); len(s) != 32 || strings.Trim(s, alphanumeric) != "" {
		t.Fatalf("RandomString=%q", s)
	}
	// 并发调用不能因共享种子得到相同结果。
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value := RandLetters(16)
			mu.Lock()
			seen[value] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 64 {
		t.Fatalf("64 次并发调用只得到 %d 个不同结果", len(seen))
	}
}
