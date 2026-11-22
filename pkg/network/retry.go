package network

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 规则请求的有界重试：扫描目标多为一次性探测，传输层失败只重试一次，退避 200ms 起、
// 最长 600ms。关闭端口这类目标会快速失败，而不是重试到整体超时。
const (
	retryMax     = 1
	retryWaitMin = 200 * time.Millisecond
	retryWaitMax = 600 * time.Millisecond
)

// 宽松回退读取的响应上限。回退只服务于返回非标准 HTTP 报文的设备，不需要完整正文。
const tolerantMaxResponse = 2 << 20

// tolerantMethods 是允许宽松回退的方法；CONNECT 与非常见方法不回退。
var tolerantMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodDelete: true, http.MethodOptions: true, http.MethodTrace: true,
}

// tolerantErrors 是触发宽松回退的标准库解析错误：对方回应的不是合法的 HTTP 报文，
// 或在响应中途断开。
var tolerantErrors = []string{"malformed HTTP response", "malformed HTTP version", "unexpected EOF"}

// doWithRetry 发送规则请求：传输层失败时按有界策略重试；对方返回非标准 HTTP 报文时
// 以原始报文重新请求一次并宽松解析（只在未配置代理时启用，与之前的版本一致）。
//
// 每次尝试都经过 requestTransport，逐次收费并检查目标；宽松回退使用与 Transport
// 相同的拨号函数，不存在绕过代理或网络策略的连接。
func (c *HTTPClient) doWithRetry(client *http.Client, req *http.Request, options OptionsRequest) (*http.Response, error) {
	ctx := req.Context()
	tolerant := options.Proxy == "" && tolerantMethods[req.Method]
	for attempt := 0; ; attempt++ {
		current := req
		if attempt > 0 {
			current = req.Clone(ctx)
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				current.Body = body
			}
		}
		resp, err := client.Do(current)
		if err == nil {
			return resp, nil
		}
		if tolerant && tolerantError(err) {
			if loose, looseErr := c.tolerantRoundTrip(req, options); looseErr == nil {
				return loose, nil
			}
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if !retryableError(err) {
			return nil, err
		}
		if attempt >= retryMax {
			return nil, fmt.Errorf("%s %s 重试 %d 次后放弃: %w", req.Method, req.URL, attempt, err)
		}
		wait := min(retryWaitMin<<attempt, retryWaitMax)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// retryableError 排除重试也不会成功的错误：网络策略拒绝、重定向超限、协议不支持、证书不受信任。
func retryableError(err error) bool {
	var denied *DeniedError
	if errors.As(err, &denied) {
		return false
	}
	message := err.Error()
	if strings.Contains(message, "stopped after") && strings.Contains(message, "redirects") || strings.Contains(message, "unsupported protocol scheme") {
		return false
	}
	var unknown x509.UnknownAuthorityError
	return !errors.As(err, &unknown)
}

func tolerantError(err error) bool {
	message := err.Error()
	for _, keyword := range tolerantErrors {
		if strings.Contains(message, keyword) {
			return true
		}
	}
	return false
}

// tolerantRoundTrip 以原始报文重发请求，读到对方关闭连接为止，再尽量按 HTTP 解析。
// 无法解析时把收到的全部内容作为 200 响应的正文，用于识别返回非标准报文的设备。
func (c *HTTPClient) tolerantRoundTrip(req *http.Request, options OptionsRequest) (*http.Response, error) {
	ctx := req.Context()
	policy, state := c.policyFor(ctx)
	info := RequestInfoFrom(ctx)
	if info.Kind == "" {
		info.Kind = RequestHTTP
	}
	target := urlTarget(info.Kind, req.URL, info, false)
	if err := checkTarget(ctx, policy, target); err != nil {
		return nil, err
	}
	if err := c.WaitRequest(ctx, req.URL.String()); err != nil {
		return nil, err
	}
	rec := RecorderFrom(ctx)
	var ex Exchange
	start := time.Now()
	if rec != nil {
		if rec.Full() {
			rec = nil
		} else {
			ex = rec.requestExchange(ctx, info.Kind, req, false)
		}
	}
	resp, err := c.tolerantExchange(ctx, req, options, target, state != nil && state.scoped)
	if rec != nil {
		if err != nil {
			rec.failed(ex, start, err)
		} else {
			rec.observeResponse(ex, resp, nil, start)
		}
	}
	return resp, err
}

// tolerantExchange 发出原始报文并读取、解析响应。
func (c *HTTPClient) tolerantExchange(ctx context.Context, req *http.Request, options OptionsRequest, target TargetRequest, scoped bool) (*http.Response, error) {
	host := target.Host
	dial, err := c.targetDialer("", scoped)
	if err != nil {
		return nil, err
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, target.Port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(options.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if req.URL.Scheme == "https" {
		config := c.transportTLSConfig()
		config.ServerName = host
		secure := tls.Client(conn, config)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = secure
	}

	var body []byte
	if req.GetBody != nil {
		reader, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		body, err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
	}
	var wire strings.Builder
	wire.WriteString(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\nHost: " + req.URL.Host + "\r\nConnection: close\r\n")
	for key, values := range req.Header {
		switch {
		case strings.EqualFold(key, "Host"), strings.EqualFold(key, "Connection"), strings.EqualFold(key, "Content-Length"), strings.EqualFold(key, "Transfer-Encoding"):
			continue
		}
		for _, value := range values {
			wire.WriteString(key + ": " + value + "\r\n")
		}
	}
	if len(body) > 0 {
		wire.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	wire.WriteString("\r\n")
	wire.Write(body)
	if _, err := io.WriteString(conn, wire.String()); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(conn, tolerantMaxResponse))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("宽松回退没有收到任何数据")
	}
	return parseTolerantResponse(raw, req), nil
}

// parseTolerantResponse 先按标准 HTTP 解析；失败时提取状态行与响应头，其余作为正文。
// 压缩正文按 Content-Encoding 解开，与 Transport 对规则呈现的内容一致。
func parseTolerantResponse(raw []byte, req *http.Request) *http.Response {
	if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req); err == nil {
		if data, readErr := io.ReadAll(resp.Body); readErr == nil {
			_ = resp.Body.Close()
			if decoded, ok := decodeContent(resp.Header.Get("Content-Encoding"), data); ok {
				data = decoded
				resp.Header.Del("Content-Encoding")
			}
			resp.Body = io.NopCloser(bytes.NewReader(data))
			resp.ContentLength = int64(len(data))
			resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
			return resp
		}
	}
	header := make(http.Header)
	status, protocol := http.StatusOK, "HTTP/1.0"
	body := raw
	if end := bytes.Index(raw, []byte("\r\n\r\n")); end >= 0 {
		head := raw[:end]
		body = raw[end+4:]
		lines := bytes.Split(head, []byte("\r\n"))
		if parts := strings.SplitN(string(bytes.TrimSpace(lines[0])), " ", 3); len(parts) >= 2 {
			protocol = parts[0]
			if code, err := strconv.Atoi(parts[1]); err == nil {
				status = code
			}
		}
		for _, line := range lines[1:] {
			if colon := bytes.IndexByte(line, ':'); colon >= 0 {
				header.Add(string(bytes.TrimSpace(line[:colon])), string(bytes.TrimSpace(line[colon+1:])))
			}
		}
	}
	if decoded, ok := decodeContent(header.Get("Content-Encoding"), body); ok {
		body = decoded
		header.Del("Content-Encoding")
	}
	if header.Get("Content-Length") == "" {
		header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/octet-stream")
	}
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         protocol,
		ProtoMajor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// decodeContent 解开 gzip 与 deflate（zlib 或裸 deflate）正文；其他编码原样返回 false。
func decodeContent(encoding string, data []byte) ([]byte, bool) {
	var reader io.ReadCloser
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		reader = gz
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			decoded, readErr := io.ReadAll(io.LimitReader(zr, tolerantMaxResponse))
			_ = zr.Close()
			if readErr == nil {
				return decoded, true
			}
		}
		reader = flate.NewReader(bytes.NewReader(data))
	default:
		return nil, false
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, tolerantMaxResponse))
	if err != nil {
		return nil, false
	}
	return decoded, true
}
