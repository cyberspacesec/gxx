// Package service 提供 GXX IDE 的业务逻辑实现。
// 每个 service 负责一类领域（请求测试 / YAML 校验 / 指纹运行 / 指纹库），
// 仅依赖 internal/model 与主项目暴露的 pkg/*。
package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	fingerpkg "github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/common"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
)

// RequestService 处理请求测试相关业务。
type RequestService struct{}

// NewRequestService 返回 RequestService 单例。
func NewRequestService() *RequestService { return &RequestService{} }

// Send 根据入参执行 HTTP 请求并返回完整响应数据。
//
// 流程：
//   - 入参校验，必填项缺失返回 400；
//   - 区分 url / raw 两种模式分发到 sendURL / sendRaw；
//   - 统一通过 buildResponse 复用主项目 finger.* 指纹辅助函数补充 title / cert / server。
func (s *RequestService) Send(ctx context.Context, in *model.SendRequestInput) (*model.SendRequestOutput, error) {
	if in == nil {
		return nil, response.NewBadRequest("缺少请求参数")
	}
	if strings.TrimSpace(in.Target) == "" && in.Mode != model.RequestModeRaw {
		return nil, response.NewBadRequest("目标 URL 不能为空")
	}
	if in.Mode == model.RequestModeRaw && strings.TrimSpace(in.Raw) == "" {
		return nil, response.NewBadRequest("Raw 报文不能为空")
	}
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch in.Mode {
	case model.RequestModeRaw:
		return sendRaw(ctx, in, timeout)
	default:
		return sendURL(ctx, in, timeout)
	}
}

func sendURL(ctx context.Context, in *model.SendRequestInput, timeout time.Duration) (*model.SendRequestOutput, error) {
	target := strings.TrimSpace(in.Target)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		if in.UseTLS {
			target = "https://" + target
		} else {
			target = "http://" + target
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}

	httpClient := network.NewHTTPClient()
	defer httpClient.Close()
	httpClient.SetInsecureSkipVerify(!in.VerifyTLS)

	opts := network.OptionsRequest{
		Proxy:              strings.TrimSpace(in.Proxy),
		Timeout:            timeout,
		FollowRedirects:    in.FollowRedirects,
		InsecureSkipVerify: !in.VerifyTLS,
		CustomHeaders:      in.Headers,
	}

	dumpReq := buildDumpRequest(method, target, in.Headers, in.Body)
	start := time.Now()
	resp, err := httpClient.SendRequestHttp(ctx, method, target, in.Body, opts)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	out := buildResponse(ctx, target, resp, dumpReq, httpClient, opts)
	out.Latency = time.Since(start).Milliseconds()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, nil
}

func sendRaw(ctx context.Context, in *model.SendRequestInput, timeout time.Duration) (*model.SendRequestOutput, error) {
	rawText := normalizeCRLF(in.Raw)
	parsed, err := parseRawHTTP(rawText)
	if err != nil {
		return nil, response.NewBadRequest(fmt.Sprintf("解析 raw 报文失败: %v", err))
	}
	host := parsed.Host
	if host == "" {
		host = normalizeRawTargetHost(in.Target)
	}
	if host == "" {
		return nil, response.NewBadRequest("raw 报文缺少 Host 头，且 target 也为空")
	}
	addr := ensurePort(host, in.UseTLS)
	conn, err := network.DialContext(ctx, "tcp", addr, strings.TrimSpace(in.Proxy), timeout, in.UseTLS, hostOnly(host), !in.VerifyTLS)
	if err != nil {
		return nil, fmt.Errorf("建立连接失败: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, werr := conn.Write([]byte(rawText)); werr != nil {
		return nil, fmt.Errorf("写入原始报文失败: %w", werr)
	}
	reader := bufio.NewReader(conn)
	resp, rerr := http.ReadResponse(reader, &http.Request{Method: parsed.Method})
	if rerr != nil {
		return nil, fmt.Errorf("读取响应失败: %w", rerr)
	}
	defer resp.Body.Close()
	finalURL := buildURLFromRaw(parsed, in.UseTLS)
	httpClient := network.NewHTTPClient()
	defer httpClient.Close()
	httpClient.SetInsecureSkipVerify(!in.VerifyTLS)
	opts := network.OptionsRequest{Proxy: in.Proxy, Timeout: timeout, FollowRedirects: in.FollowRedirects, InsecureSkipVerify: !in.VerifyTLS, CustomHeaders: in.Headers}
	out := buildResponse(ctx, finalURL, resp, rawText, httpClient, opts)
	out.Latency = time.Since(start).Milliseconds()
	if in.UseTLS {
		if tc, ok := conn.(*tls.Conn); ok {
			connState := tc.ConnectionState()
			fakeResp := &http.Response{TLS: &connState}
			out.Certs = extractCertSummary(fakeResp)
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, nil
}

// ---- 私有辅助 ---------------------------------------------------------

type rawHTTPInfo struct {
	Method  string
	Path    string
	Host    string
	Headers http.Header
}

func parseRawHTTP(raw string) (*rawHTTPInfo, error) {
	br := bufio.NewReader(strings.NewReader(raw))
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("读取请求行失败: %w", err)
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("非法请求行: %q", line)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("读取请求头失败: %w", err)
	}
	info := &rawHTTPInfo{
		Method:  parts[0],
		Path:    parts[1],
		Headers: http.Header(hdr),
	}
	info.Host = info.Headers.Get("Host")
	return info, nil
}

func normalizeCRLF(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\n", "\r\n")
	if !strings.HasSuffix(raw, "\r\n\r\n") {
		raw += "\r\n\r\n"
	}
	return raw
}

func ensurePort(host string, tls bool) string {
	if strings.Contains(host, ":") {
		return host
	}
	if tls {
		return host + ":443"
	}
	return host + ":80"
}

func normalizeRawTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
}

func hostOnly(host string) string {
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func buildURLFromRaw(info *rawHTTPInfo, tls bool) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	host := info.Host
	if host == "" {
		host = "unknown"
	}
	return scheme + "://" + host + info.Path
}

func buildDumpRequest(method, target string, headers map[string]string, body string) string {
	var sb strings.Builder
	u, _ := url.Parse(target)
	path := "/"
	if u != nil && u.RequestURI() != "" {
		path = u.RequestURI()
	}
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	if u != nil && u.Host != "" {
		sb.WriteString("Host: ")
		sb.WriteString(u.Host)
		sb.WriteString("\r\n")
	}
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func buildResponse(ctx context.Context, target string, resp *http.Response, requestRaw string, client *network.HTTPClient, opts network.OptionsRequest) *model.SendRequestOutput {
	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		headers[k] = strings.Join(vs, ", ")
	}
	rawHeader := buildRawHeader(resp)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, network.MaxDefaultBody))
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	bodyStr, isBase64 := encodeBody(bodyBytes)

	out := &model.SendRequestOutput{
		Status:       resp.StatusCode,
		StatusText:   resp.Status,
		Headers:      headers,
		RawHeader:    rawHeader,
		Body:         bodyStr,
		BodyIsBase64: isBase64,
		BodyBytes:    len(bodyBytes),
		FinalURL:     resolveFinalURL(target, resp),
		RequestRaw:   requestRaw,
	}
	out.Certs = extractCertSummary(resp)
	out.Title = fingerpkg.GetTitleFromBody(ctx, out.FinalURL, resp, bodyBytes, client, opts)
	if si := fingerpkg.GetServerInfoFromResponse(resp); si != nil {
		out.Server = strings.TrimSpace(si.OriginalServer)
	}
	if isHTMLContent(resp.Header.Get("Content-Type")) {
		out.IconHash = fingerpkg.GetPageIconHash(ctx, client, out.FinalURL, bodyBytes, opts)
	}
	return out
}

func buildRawHeader(resp *http.Response) string {
	var b strings.Builder
	b.WriteString(resp.Proto)
	b.WriteByte(' ')
	b.WriteString(resp.Status)
	b.WriteString("\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

func resolveFinalURL(target string, resp *http.Response) string {
	if resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.String()
	}
	return target
}

func encodeBody(body []byte) (string, bool) {
	if utf8.Valid(body) {
		nonPrint := 0
		for _, b := range body {
			if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
				nonPrint++
				if nonPrint > 16 {
					return string(common.Base64Encode(body)), true
				}
			}
		}
		return string(body), false
	}
	return string(common.Base64Encode(body)), true
}

func extractCertSummary(resp *http.Response) []model.CertSummary {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	certInfos := fingerpkg.GetCertInfos(resp)
	ciMap := make(map[string]*types.CertInfo, len(certInfos))
	for _, ci := range certInfos {
		if ci != nil {
			ciMap[ci.SerialNumber] = ci
		}
	}

	now := time.Now().UTC()
	rawCerts := resp.TLS.PeerCertificates
	out := make([]model.CertSummary, 0, len(rawCerts))
	for _, c := range rawCerts {
		if c == nil {
			continue
		}
		cs := model.CertSummary{
			Subject: model.CertName{
				CommonName:         c.Subject.CommonName,
				Organization:       append([]string{}, c.Subject.Organization...),
				OrganizationalUnit: append([]string{}, c.Subject.OrganizationalUnit...),
				Country:            append([]string{}, c.Subject.Country...),
				Province:           append([]string{}, c.Subject.Province...),
				Locality:           append([]string{}, c.Subject.Locality...),
			},
			SubjectDN: c.Subject.String(),
			Issuer: model.CertName{
				CommonName:         c.Issuer.CommonName,
				Organization:       append([]string{}, c.Issuer.Organization...),
				OrganizationalUnit: append([]string{}, c.Issuer.OrganizationalUnit...),
				Country:            append([]string{}, c.Issuer.Country...),
				Province:           append([]string{}, c.Issuer.Province...),
				Locality:           append([]string{}, c.Issuer.Locality...),
			},
			IssuerDN:           c.Issuer.String(),
			NotBefore:          c.NotBefore.UTC().Format("2006-01-02 15:04:05"),
			NotAfter:           c.NotAfter.UTC().Format("2006-01-02 15:04:05"),
			Valid:              !(now.Before(c.NotBefore.UTC()) || now.After(c.NotAfter.UTC())),
			SerialNumber:       c.SerialNumber.String(),
			PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
			Version:            c.Version,
			DNSNames:           append([]string{}, c.DNSNames...),
		}
		if ci, ok := ciMap[cs.SerialNumber]; ok {
			cs.PublicKey = ci.PublicKey
			cs.IPAddresses = ci.IPAddresses
			cs.EmailAddresses = ci.EmailAddresses
			cs.OCSPServer = ci.OCSPServer
			cs.CRLDistributionPoints = ci.CRLDistributionPoints
		}
		out = append(out, cs)
	}
	return out
}

func isHTMLContent(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "text/html") || strings.Contains(lower, "application/xhtml")
}
