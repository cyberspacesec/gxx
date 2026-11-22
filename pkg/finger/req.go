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
	"net/url"
	"sort"
	"strings"
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
	return buildProtoResponsePage(ctx, resp, body, latency, client, options, "", true)
}

func buildProtoResponsePage(ctx context.Context, resp *http.Response, body []byte, latency int64, client *network.HTTPClient, options network.OptionsRequest, pageURL string, icon bool) *proto.Response {
	headers := make(map[string]string, len(resp.Header))
	rawHeaderBuilder := strings.Builder{}
	rawHeaderBuilder.WriteString(resp.Proto)
	rawHeaderBuilder.WriteString(" ")
	rawHeaderBuilder.WriteString(resp.Status)
	rawHeaderBuilder.WriteString("\n")
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[strings.ToLower(k)] = strings.Join(vals, ", ")
		}
	}
	// 原始响应头按服务器发送的顺序逐行写入，多值头（如 Set-Cookie）各占一行。
	writeHeaderLines(&rawHeaderBuilder, resp.Header, network.ResponseHeaderOrder(resp))
	// 入口页使用最终重定向地址解析资源；规则响应仅在根路径提取。
	var iconHashStr = ""
	if icon && resp.Request != nil && resp.Request.URL != nil && resp.Request.Method == http.MethodGet {
		path := resp.Request.URL.Path
		// 30x 响应不是浏览器会渲染的页面，不为它下载图标。
		if (pageURL != "" || path == "" || path == "/") && (resp.StatusCode < 300 || resp.StatusCode >= 400) && isHTMLResponse(resp, body) {
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
	out := &proto.Response{
		Status:      int32(resp.StatusCode),
		Url:         network.Url2ProtoUrl(resp.Request.URL),
		Headers:     headers,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		Raw:         raw,
		RawHeader:   []byte(rawHeader),
		Latency:     latency,
		IconHash:    iconHashStr,
		Jarm:        network.JARMFrom(ctx),
	}
	if info, ok := network.ResponseTLS(resp); ok {
		out.TlsVersion, out.CipherSuite, out.Ja3S = info.Version, info.CipherSuite, info.JA3S
	}
	return out
}

// writeHeaderLines 按 order 给出的名称顺序写入响应头；order 中没有的值按名称排序写在最后。
// order 为空时（无法记录顺序的响应）整体按名称排序，结果与读取次序无关。
func writeHeaderLines(b *strings.Builder, header http.Header, order []string) {
	used := make(map[string]int, len(order))
	write := func(key, value string) {
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\n")
	}
	for _, name := range order {
		key := http.CanonicalHeaderKey(name)
		values := header[key]
		if index := used[key]; index < len(values) {
			write(key, values[index])
			used[key] = index + 1
		}
	}
	if len(used) == len(header) {
		complete := true
		for key, values := range header {
			if used[key] < len(values) {
				complete = false
				break
			}
		}
		if complete {
			return
		}
	}
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range header[key][used[key]:] {
			write(key, value)
		}
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
	body = decodeHTMLBody(body, responseContentType(resp))
	return buildProtoResponseBody(ctx, resp, body, latency, client, options)
}

// responseContentType 安全读取响应的 Content-Type（resp/Header 可能为 nil）。
func responseContentType(resp *http.Response) string {
	if resp == nil || resp.Header == nil {
		return ""
	}
	return resp.Header.Get("Content-Type")
}

// BuildPageResponseOwned 构造入口跳转链上一页的响应，接管独占正文。
// pageURL 是该页的实际地址，用于解析页面资源；icon 为 false 时不下载图标
// （跳转链的中间页只参与规则匹配）。
func BuildPageResponseOwned(ctx context.Context, resp *http.Response, body []byte, client *network.HTTPClient, options network.OptionsRequest, pageURL string, icon bool) *proto.Response {
	body = decodeHTMLBody(body, responseContentType(resp))
	return buildProtoResponsePage(ctx, resp, body, 0, client, options, pageURL, icon)
}

// TargetRequest 用目标地址合成只含 Url 的请求，使 set 块在发出任何请求之前
// 就能求值 request.url.host、request.url.domain 等变量。未带协议时按 https 解析。
func TargetRequest(target string) *proto.Request {
	raw := strings.TrimSpace(target)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return &proto.Request{Url: &proto.UrlType{}}
	}
	return &proto.Request{Method: http.MethodGet, Url: network.Url2ProtoUrl(u)}
}
