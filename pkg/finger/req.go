/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: req.go
    @Date: 2025/2/21 下午3:06*
*/
package finger

import (
	"context"
	"fmt"

	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"net/http"
	"strings"
	"unicode/utf8"
)

// formatPath 格式化路径
func formatPath(path string) string {
	newPath := strings.TrimSpace(path)
	if strings.HasPrefix(newPath, "^") {
		newPath = "/" + newPath[1:]
	}
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	newPath = strings.ReplaceAll(newPath, " ", "%20")
	newPath = strings.ReplaceAll(newPath, "#", "%23")
	return newPath
}

// formatBody 格式化请求体
func formatBody(body, contentType string, variableMap map[string]any) string {
	body = SetVariableMap(strings.TrimSpace(body), variableMap)
	if strings.HasPrefix(strings.ToLower(contentType), "multipart/form-data") && strings.Contains(body, "\n\n") {
		multipartBody, err := common.DealMultipart(contentType, body)
		if err != nil {
			logger.Debug("处理 multipart/form-data 出错: %v", err)
			return body
		}
		body = SetVariableMap(strings.TrimSpace(multipartBody), variableMap)
	}
	return body
}

// buildProtoRequest 构造proto.Request结构体
func buildProtoRequest(resp *http.Response, req RuleRequest) *proto.Request {
	protoReq := &proto.Request{
		Method:      req.Method,
		Url:         network.Url2ProtoUrl(resp.Request.URL),
		ContentType: resp.Request.Header.Get("Content-Type"),
		Body:        []byte(req.Body),
	}
	headers := make(map[string]string)
	rawReqHeaderBuilder := strings.Builder{}
	for k := range resp.Request.Header {
		headers[k] = resp.Request.Header.Get(k)
		rawReqHeaderBuilder.WriteString(k)
		rawReqHeaderBuilder.WriteString(": ")
		rawReqHeaderBuilder.WriteString(resp.Request.Header.Get(k))
		rawReqHeaderBuilder.WriteString("\n")
	}
	if resp.Request.URL.Path == "" {
		resp.Request.URL.Path = "/"
	}
	protoReq.Headers = headers
	protoReq.Raw = []byte(fmt.Sprintf("%s %s %s\nHost: %s\n%s\n\n%s", req.Method, resp.Request.URL.Path, resp.Proto, resp.Request.URL.Host, strings.Trim(rawReqHeaderBuilder.String(), "\n"), req.Body))
	protoReq.RawHeader = []byte(strings.Trim(rawReqHeaderBuilder.String(), "\n"))

	return protoReq
}

func buildProtoResponseBody(ctx context.Context, resp *http.Response, body []byte, latency int64, client *network.HTTPClient, options network.OptionsRequest) *proto.Response {
	return buildProtoResponsePage(ctx, resp, body, latency, client, options, "")
}

func buildProtoResponsePage(ctx context.Context, resp *http.Response, body []byte, latency int64, client *network.HTTPClient, options network.OptionsRequest, pageURL string) *proto.Response {
	headers := make(map[string]string)
	rawHeaderBuilder := strings.Builder{}
	rawHeaderBuilder.WriteString(resp.Proto)
	rawHeaderBuilder.WriteString(" ")
	rawHeaderBuilder.WriteString(resp.Status)
	rawHeaderBuilder.WriteString("\n")
	for k := range resp.Header {
		// 按多值逐行写入，避免 Set-Cookie 等多值头被覆盖
		vals := resp.Header[k]
		if len(vals) == 0 {
			continue
		}
		headers[strings.ToLower(k)] = strings.Join(vals, ", ")
		for _, v := range vals {
			rawHeaderBuilder.WriteString(k)
			rawHeaderBuilder.WriteString(": ")
			rawHeaderBuilder.WriteString(v)
			rawHeaderBuilder.WriteString("\n")
		}
	}
	// 入口页使用最终重定向地址解析资源；规则响应仅在根路径提取。
	var iconHashStr = ""
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.Method == http.MethodGet {
		path := resp.Request.URL.Path
		if (pageURL != "" || path == "" || path == "/") && isHTMLResponse(resp, body) {
			if pageURL == "" {
				pageURL = resp.Request.URL.String()
			}
			iconHashStr = GetPageIconHash(ctx, client, pageURL, body, options)
		}
	}
	rawHeader := strings.Trim(rawHeaderBuilder.String(), "\n")
	// 直接写入最终字节数组，避免格式化缓冲、整段字符串及 []byte 的多次正文复制。
	raw := make([]byte, len(rawHeader)+2+len(body))
	n := copy(raw, rawHeader)
	raw[n], raw[n+1] = '\n', '\n'
	copy(raw[n+2:], body)
	return &proto.Response{
		Status:      int32(resp.StatusCode),
		Url:         network.Url2ProtoUrl(resp.Request.URL),
		Headers:     headers,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		Raw:         raw,
		RawHeader:   []byte(rawHeader),
		Latency:     latency,
		IconHash:    iconHashStr,
	}
}

func isHTMLResponse(resp *http.Response, body []byte) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml") {
		return true
	}
	if ct == "" || strings.HasPrefix(ct, "application/octet-stream") {
		return strings.HasPrefix(http.DetectContentType(body[:min(len(body), 512)]), "text/html")
	}
	return false
}

// BuildProtoRequest 构造proto.Request结构体 (公开版本)
func BuildProtoRequest(resp *http.Response, method, body, path string) *proto.Request {
	var req RuleRequest
	req.Method = method
	req.Body = body
	req.Path = path
	return buildProtoRequest(resp, req)
}

// BuildProtoResponseOwned 接管独占正文，UTF-8 输入直接作为只读消息正文。
// 调用后不得修改输入；GB18030 回退与字符串入口一致。Raw 与 Body 仍使用
// 各自的数组，消息发布后可由同次扫描中的规则共享读取。
func BuildProtoResponseOwned(ctx context.Context, resp *http.Response, body []byte, latency int64, client *network.HTTPClient, options network.OptionsRequest) *proto.Response {
	if !utf8.Valid(body) {
		body = []byte(common.Str2UTF8(string(body)))
	}
	return buildProtoResponseBody(ctx, resp, body, latency, client, options)
}

// BuildBaseProtoResponseOwned 构造扫描入口响应。pageURL 为最终页面地址，
// 仅用于资源解析；规则缓存和 proto.Response.Url 继续使用目标地址。
func BuildBaseProtoResponseOwned(ctx context.Context, resp *http.Response, body []byte, latency int64, client *network.HTTPClient, options network.OptionsRequest, pageURL string) *proto.Response {
	if !utf8.Valid(body) {
		body = []byte(common.Str2UTF8(string(body)))
	}
	return buildProtoResponsePage(ctx, resp, body, latency, client, options, pageURL)
}
