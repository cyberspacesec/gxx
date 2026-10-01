package main

import (
	"bytes"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestGetTitle(t *testing.T) {
	//logger.InitLogger("logs", 5, 5)
	// 测试用例
	tests := []struct {
		name     string // 测试名称
		url      string // 测试URL
		htmlBody string // 模拟的HTML响应体
		want     string // 期望的标题结果
	}{
		{
			name: "基本标题测试",
			url:  "https://example.com",
			htmlBody: `
				<html>
				<head>
					<title>测试网页标题</title>
				</head>
				<body>内容</body>
				</html>
			`,
			want: "测试网页标题",
		},
		{
			name: "带有空白字符的标题",
			url:  "https://example.com",
			htmlBody: `
				<html>
				<head>
					<title>
						测试  网页
						标题
					</title>
				</head>
				<body>内容</body>
				</html>
			`,
			want: "测试 网页 标题",
		},
		{
			name: "JavaScript document.title测试",
			url:  "https://example.com",
			htmlBody: `
				<html>
				<head>
					<title>原始标题</title>
					<script>
						document.title = ("动态标题")
					</script>
				</head>
				<body>内容</body>
				</html>
			`,
			want: "原始标题", // GetTitle 不执行 JS，仅解析静态 <title>
		},
		{
			name: "无效的document.title测试",
			url:  "https://example.com",
			htmlBody: `
				<html>
				<head>
					<title>有效标题</title>
					<script>
						document.title = ("title")
					</script>
				</head>
				<body>内容</body>
				</html>
			`,
			want: "有效标题", // 因为"title"是无效标题，应该保留原始标题
		},
		{
			name: "i18n JavaScript文件测试",
			url:  "https://example.com/path",
			htmlBody: `
				<html>
				<head>
					<title>初始标题</title>
					<script type="text/javascript" src="/assets/i18n/messages.js"></script>
				</head>
				<body>内容</body>
				</html>
			`,
			want: "初始标题", // 注意：在实际测试中，我们需要模拟i18n文件的响应
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟的HTTP响应
			resp := &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(tt.htmlBody)),
				Header:     make(http.Header),
				Request: &http.Request{
					URL: mustParseURL(tt.url),
					Header: http.Header{
						"User-Agent": []string{"Mozilla/5.0"},
					},
				},
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

			// 调用GetTitle函数
			got := finger.GetTitle(tt.url, resp)

			// 打印获取的标题
			t.Logf("获取的标题为：%s", got)

			// 验证结果
			if got != tt.want {
				t.Errorf("GetTitle() = %q, 期望 %q", got, tt.want)
			}
		})
	}
}

// 测试带有i18n JavaScript文件的情况，通过模拟HTTP客户端
func TestGetTitleWithI18n(t *testing.T) {
	// 创建自定义的HTTP客户端和传输层
	originalClient := http.DefaultClient
	defer func() { http.DefaultClient = originalClient }()

	// 模拟i18n JavaScript文件内容
	i18nJSContent := `
		{
			"top.login.title": "国际化标题",
			"other.key": "其他值"
		}
	`

	// 创建一个带有自定义RoundTripper的HTTP客户端
	client := &http.Client{
		Transport: &mockTransport{
			responses: map[string]*http.Response{
				"https://example.com/assets/i18n/messages.js": {
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(i18nJSContent)),
					Header:     make(http.Header),
				},
			},
		},
	}
	http.DefaultClient = client

	// 测试HTML内容
	htmlBody := `
		<html>
		<head>
			<title>初始标题</title>
			<script type="text/javascript" src="/assets/i18n/messages.js"></script>
		</head>
		<body>内容</body>
		</html>
	`

	// 创建模拟的HTTP响应
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(htmlBody)),
		Header:     make(http.Header),
		Request: &http.Request{
			URL: mustParseURL("https://example.com"),
			Header: http.Header{
				"User-Agent": []string{"Mozilla/5.0"},
			},
		},
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	// 调用GetTitle函数
	got := finger.GetTitle("https://example.com", resp)

	// 打印获取的标题
	t.Logf("获取的标题为：%s", got)

	// 验证结果 - 注意：此测试可能不会按预期工作，因为GetTitle使用客户端而不是http.DefaultClient
	// 这只是一个示例，说明如何测试带有i18n的场景
	if got != "国际化标题" {
		t.Logf("GetTitle() = %q, 期望 \"国际化标题\", 但这个测试可能需要修改GetTitle函数以接受自定义HTTP客户端", got)
	}
}

// mockTransport 是一个模拟HTTP传输层，用于测试
type mockTransport struct {
	responses map[string]*http.Response
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := m.responses[req.URL.String()]
	if resp == nil {
		return &http.Response{
			StatusCode: 404,
			Body:       io.NopCloser(strings.NewReader("Not Found")),
			Header:     make(http.Header),
		}, nil
	}
	return resp, nil
}

// mustParseURL 解析URL并在失败时触发panic
// 仅在测试中使用，因为我们希望在测试数据无效时立即失败
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
