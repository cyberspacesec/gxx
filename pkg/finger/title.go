/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: title.go
    @Date: 2025/4/3 上午9:47*
*/
package finger

import (
	"bytes"
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// GetTitle 从网页中提取标题
func GetTitle(urlStr string, resp *http.Response) string {
	body, err := network.ReadResponseBody(resp, network.MaxDefaultBody)
	_ = resp.Body.Close()
	if err != nil {
		return ""
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	return GetTitleFromBody(ctx, urlStr, resp, body, network.DefaultHTTPClient(), network.OptionsRequest{Timeout: network.DefaultTimeout, FollowRedirects: true})
}

// GetTitleFromBody 消费已限长的正文，附加资源继承同一次扫描的请求策略。
func GetTitleFromBody(ctx context.Context, urlStr string, resp *http.Response, bodyBytes []byte, client *network.HTTPClient, options network.OptionsRequest) string {
	// 解析字符集并转换编码
	body := bodyBytes
	contentType := resp.Header.Get("Content-Type")

	// 检查和处理编码
	charsetRegex := titlePattern1
	charsetMatch := charsetRegex.FindStringSubmatch(contentType)
	if len(charsetMatch) < 2 {
		// 如果 HTTP 头中没有指定字符集，尝试从 HTML 内容中查找
		metaCharsetRegex := titlePattern2
		metaMatch := metaCharsetRegex.FindSubmatch(body)
		if len(metaMatch) >= 2 {
			charsetMatch = []string{"", string(metaMatch[1])}
		}
	}

	// 根据检测到的字符集进行转换
	if len(charsetMatch) >= 2 {
		charset := strings.ToLower(charsetMatch[1])
		logger.FromContext(ctx).Debug("检测到字符集: %s", charset)

		if charset != "utf-8" && charset != "utf8" {
			// 使用 common.Str2UTF8 函数转换为 UTF-8
			body = titleUTF8Bytes(body)
			logger.FromContext(ctx).Debug("已将内容从 %s 转换为 UTF-8", charset)
		}
	} else {
		// 如果无法检测到字符集，尝试转换为 UTF-8
		body = titleUTF8Bytes(body)
	}

	// 解析URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		logger.FromContext(ctx).Debug("解析URL出错: %v", err)
		return ""
	}

	// 获取基础URL
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
	basePath := parsedURL.Path

	var title string
	var titleURL string

	// 使用正则表达式查找标题，使用(?s)模式修饰符支持跨行匹配
	titleRegex := titlePattern3
	titleMatches := titleRegex.FindSubmatch(body)
	if len(titleMatches) > 1 {
		title = cleanTitle(string(titleMatches[1]))
		logger.FromContext(ctx).Debug("通过正则表达式识别到标题: %s", title)
	}

	// 在JavaScript中查找document.title
	domTitleRegex := titlePattern4
	var domTitleMatches [][]byte
	// 该模式必须含左括号；缺失时无需运行整页正则。
	if bytes.Contains(body, []byte("(")) {
		domTitleMatches = domTitleRegex.FindSubmatch(body)
	}
	if len(domTitleMatches) > 1 {
		domSource := string(domTitleMatches[1])
		logger.FromContext(ctx).Debug("识别到DOM渲染的标题: %s", domSource)
		domTitle := strings.ReplaceAll(domSource, "\"", "")

		invalidTitles := []string{"title", ".title", "top.", ".login", "=", "||", "''", "null"}
		isInvalid := false
		for _, invalid := range invalidTitles {
			if strings.Contains(domTitle, invalid) {
				isInvalid = true
				break
			}
		}
		if !isInvalid && len(domTitle) > 0 {
			lowerDomTitle := strings.ToLower(domTitle)
			if !strings.Contains(lowerDomTitle, "null") && !strings.Contains(lowerDomTitle, "--") && !strings.Contains(title, ".title") && !strings.Contains(title, "document") && len(title)-len(domTitle) > 30 {
				logger.FromContext(ctx).Debug("DOM标题符合要求，更新标题")
				title = domTitle
			} else {
				logger.FromContext(ctx).Debug("DOM标题不符合要求，跳过")
			}
		} else {
			logger.FromContext(ctx).Debug("DOM标题不符合要求，跳过")
		}

	}

	// 查找i18n JavaScript文件
	i18nRegex := titlePattern5
	// 可用脚本的原始地址必须同时包含这两个区分大小写的片段。
	hasI18nSource := bytes.Contains(body, []byte("i18n")) && bytes.Contains(body, []byte(".js"))
	// 只消费到第一个适用的脚本，不保留页面内全部脚本的匹配切片。
	for start := 0; hasI18nSource && start < len(body); {
		match := i18nRegex.FindSubmatchIndex(body[start:])
		if match == nil {
			break
		}
		source := string(body[start+match[2] : start+match[3]])
		start += match[1]
		if strings.HasSuffix(source, ".js") && strings.Contains(source, "i18n") {
			path := strings.TrimPrefix(source, "/")
			if strings.HasPrefix(path, basePath) {
				titleURL = baseURL + path
			} else {
				titleURL = baseURL + strings.TrimSuffix(basePath, "/") + "/" + path
			}
			break
		}
	}

	// 尝试从i18n JavaScript文件获取标题
	if titleURL != "" {
		logger.FromContext(ctx).Debug("识别到国际化，从i18n JS文件获取标题数据")

		retries := 3
		for i := 0; i < retries; i++ {
			respTitle, err := client.SendRequestHttp(ctx, http.MethodGet, titleURL, "", options)
			if err != nil {
				logger.FromContext(ctx).Debug("获取i18n JS文件出错: %v", err)
				continue
			}

			if respTitle.StatusCode != http.StatusOK {
				_ = respTitle.Body.Close()
				break
			}
			bodyBytes, err := network.ReadResponseBody(respTitle, network.MaxDefaultBody)
			_ = respTitle.Body.Close()
			if err != nil {
				logger.FromContext(ctx).Debug("读取i18n JS响应出错: %v", err)
				break
			}

			jsContent := titleUTF8Bytes(bodyBytes)
			titleRegex := titlePattern6
			titleMatches := titleRegex.FindSubmatch(jsContent)
			if len(titleMatches) > 1 {
				jsTitle := string(titleMatches[1])
				logger.FromContext(ctx).Debug("成功从i18n JS文件获取标题数据: %s", jsTitle)
				title = jsTitle
				logger.FromContext(ctx).Debug("找到新标题，替换原始标题: %s", title)
			}
			break
		}
	}

	// 返回值可能来自整页 HTML 或脚本的子串，结果只持有标题本身。
	return strings.Clone(title)
}

// 合法 UTF-8 正文保持只读字节视图，编码回退才建立转换后的独立数组。
func titleUTF8Bytes(body []byte) []byte {
	if utf8.Valid(body) {
		return body
	}
	return []byte(common.Str2UTF8(string(body)))
}

// cleanTitle 移除空白字符并清理标题字符串
func cleanTitle(title string) string {
	// 先确保标题是UTF-8编码
	title = common.Str2UTF8(title)

	// 移除制表符、换行符和回车符
	title = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' ' // 将这些字符替换为空格，而不是删除它们
		}
		return r
	}, title)

	// 将多个空格替换为单个空格
	space := false
	title = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			if space {
				return -1
			}
			space = true
			return ' '
		}
		space = false
		return r
	}, title)

	return strings.TrimSpace(title)
}

var (
	titlePattern1 = regexp.MustCompile(`(?i)charset=["']?([\w-]+)["']?`)
	titlePattern2 = regexp.MustCompile(`(?i)<meta\s+.*?charset=["']?([\w-]+)["']?.*?>`)
	titlePattern3 = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	titlePattern4 = regexp.MustCompile(`(?i)document\.title.*?=.*?\((.*?)\)`)
	titlePattern5 = regexp.MustCompile(`(?i)type="text/javascript".*?src="(.*?)"`)
	titlePattern6 = regexp.MustCompile(`"top\.login\.title": "(.*?)",`)
)
