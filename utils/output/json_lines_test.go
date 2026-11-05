package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// CLI 的 JSON 输出必须是 JSON Lines：每个目标恰好一行，可被逐行解析。
func TestJSONOutputIsOneObjectPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	targets := []string{"http://a.example.com", "http://b.example.com"}
	for _, target := range targets {
		err := WriteFingerprints(&WriteOptions{
			Output: path, Format: "json", Target: target, StatusCode: 200, Title: "标题",
			RespHeaders: "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html", FinalResult: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := CloseFileOutput(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := 0
	for scanner.Scan() {
		var record JSONOutput
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("第 %d 行不是完整的 JSON 对象: %v\n%s", lines+1, err, scanner.Text())
		}
		if record.URL != targets[lines] || record.Headers == "" {
			t.Fatalf("第 %d 行内容错误: %+v", lines+1, record)
		}
		lines++
	}
	if lines != len(targets) {
		t.Fatalf("%d 条结果写成了 %d 行", len(targets), lines)
	}
}
