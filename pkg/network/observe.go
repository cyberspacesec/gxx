package network

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"sync"
	"time"
)

// Exchange 是一次请求与响应的记录。Cached 为 true 表示规则复用了本次扫描中已取得的
// 响应，没有发出新请求；此时正文与响应头与原始记录相同。
//
// BodyBytes 与 BodySHA256 覆盖引擎实际读取的全部正文（经 net/http 的分块与压缩解码），
// ResponseBody 是其中前 MaxBody 字节；BodyTruncated 为 true 表示 ResponseBody 短于
// BodyBytes，或正文达到引擎的读取上限、没有读到结尾。
//
// Latency 是从发出请求到正文关闭（或出错）的耗时，Cached 记录为 0。
//
// 记录中的切片与映射只读，多个记录可能共用同一份数据；回调需要保留时自行复制。
type Exchange struct {
	Sequence            int
	Kind                RequestKind
	RuleID              string
	SubRule             string
	Method              string
	URL                 string
	Redirect            bool
	StatusCode          int
	RequestHeader       http.Header
	ResponseHeader      http.Header
	ResponseHeaderOrder []string
	ResponseBody        []byte
	BodyTruncated       bool
	BodyBytes           int64
	BodySHA256          string
	Certificates        []*x509.Certificate
	Latency             time.Duration
	Cached              bool
	Err                 error
}

// ExchangeLimits 限制交换记录的大小与数量。零值字段取默认值；MaxBody、MaxHeader
// 为负数时不复制正文或响应头（BodyBytes 与 BodySHA256 照常计算）。
type ExchangeLimits struct {
	MaxBody      int // 每条记录复制的正文字节上限，默认 64 KiB
	MaxHeader    int // 每条记录复制的请求头与响应头各自的字节上限，默认 64 KiB
	MaxExchanges int // 一次扫描最多回调的记录数，默认 10000
}

const (
	defaultExchangeBody  = 64 << 10
	defaultExchangeHead  = 64 << 10
	defaultExchangeCount = 10000
	maxExchangeError     = 512
)

// Recorder 收集一次扫描的交换记录，按完成顺序编号并串行回调。
type Recorder struct {
	observe func(Exchange)
	limits  ExchangeLimits

	mu      sync.Mutex
	seq     int
	pending map[*http.Response]*observedBody
	bound   map[any]*observedBody
}

// NewRecorder 创建一次扫描的记录器；observe 在发出请求的协程中串行调用，应尽快返回。
func NewRecorder(observe func(Exchange), limits ExchangeLimits) *Recorder {
	if limits.MaxBody == 0 {
		limits.MaxBody = defaultExchangeBody
	}
	if limits.MaxHeader == 0 {
		limits.MaxHeader = defaultExchangeHead
	}
	if limits.MaxExchanges <= 0 {
		limits.MaxExchanges = defaultExchangeCount
	}
	return &Recorder{observe: observe, limits: limits}
}

type recorderKey struct{}

// WithRecorder 让 ctx 下的请求向 rec 报告交换记录。
func WithRecorder(ctx context.Context, rec *Recorder) context.Context {
	if rec == nil {
		return ctx
	}
	return context.WithValue(ctx, recorderKey{}, rec)
}

// RecorderFrom 返回 ctx 中的记录器；没有时为 nil。
func RecorderFrom(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(recorderKey{}).(*Recorder)
	return rec
}

// full 报告是否已达到记录上限；调用方持有 mu。
func (r *Recorder) full() bool { return r.seq >= r.limits.MaxExchanges }

// Full 报告是否已达到记录上限，达到后不再采集新的记录。
func (r *Recorder) Full() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.full()
}

// emit 编号并回调；达到上限后丢弃。
func (r *Recorder) emit(ex Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.full() {
		return
	}
	r.seq++
	ex.Sequence = r.seq
	if r.observe != nil {
		r.observe(ex)
	}
}

// copyHeader 复制请求头或响应头，总字节数不超过 MaxHeader。
func (r *Recorder) copyHeader(header http.Header) http.Header {
	if r.limits.MaxHeader < 0 || header == nil {
		return nil
	}
	out := make(http.Header, len(header))
	budget := r.limits.MaxHeader
	for key, values := range header {
		for _, value := range values {
			size := len(key) + len(value)
			if size > budget {
				return out
			}
			budget -= size
			out[key] = append(out[key], value)
		}
	}
	return out
}

// boundedError 截断错误文本，不把任意长度的远端内容写进记录。
func boundedError(err error) error {
	if err == nil {
		return nil
	}
	if text := err.Error(); len(text) > maxExchangeError {
		return &truncatedError{text: truncateText(text, maxExchangeError), err: err}
	}
	return err
}

type truncatedError struct {
	text string
	err  error
}

func (e *truncatedError) Error() string { return e.text }
func (e *truncatedError) Unwrap() error { return e.err }

// truncateText 在 UTF-8 字符边界处截断。
func truncateText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	end := limit
	for end > 0 && text[end]&0xC0 == 0x80 {
		end--
	}
	return text[:end] + "…"
}

// requestExchange 由请求生成记录的公共字段。
func (r *Recorder) requestExchange(ctx context.Context, kind RequestKind, req *http.Request, redirect bool) Exchange {
	info := RequestInfoFrom(ctx)
	return Exchange{Kind: kind, RuleID: info.RuleID, SubRule: info.SubRule, Method: req.Method, URL: req.URL.String(), Redirect: redirect || info.Redirect, RequestHeader: r.copyHeader(req.Header)}
}

// failed 记录没有得到响应的请求。
func (r *Recorder) failed(ex Exchange, start time.Time, err error) {
	ex.Latency, ex.Err = time.Since(start), boundedError(err)
	r.emit(ex)
}

// observe 包装响应正文：边读边计算摘要并保留前 MaxBody 字节，关闭时回调。
func (r *Recorder) observeResponse(ex Exchange, resp *http.Response, order []string, start time.Time) {
	ex.StatusCode = resp.StatusCode
	ex.ResponseHeader = r.copyHeader(resp.Header)
	ex.ResponseHeaderOrder = order
	if resp.TLS != nil {
		ex.Certificates = resp.TLS.PeerCertificates
	}
	body := &observedBody{ReadCloser: resp.Body, owner: r, exchange: ex, start: start, hash: sha256.New()}
	resp.Body = body
	r.mu.Lock()
	if r.pending == nil {
		r.pending = make(map[*http.Response]*observedBody)
	}
	r.pending[resp] = body
	r.mu.Unlock()
}

// Bind 把由 resp 构造的响应对象 value 与其记录关联，规则复用该对象时据此生成缓存记录。
func (r *Recorder) Bind(resp *http.Response, value any) {
	if r == nil || resp == nil || value == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	body, ok := r.pending[resp]
	if !ok {
		return
	}
	if r.bound == nil {
		r.bound = make(map[any]*observedBody)
	}
	r.bound[value] = body
}

// Cached 报告规则复用了响应对象 value。kind、规则与子规则取自 ctx 的请求标注。
func (r *Recorder) Cached(ctx context.Context, value any, fallback Exchange) {
	if r == nil {
		return
	}
	info := RequestInfoFrom(ctx)
	r.mu.Lock()
	body := r.bound[value]
	var ex Exchange
	if body != nil && body.final != nil {
		ex = *body.final
	} else {
		ex = fallback
	}
	r.mu.Unlock()
	ex.Kind, ex.RuleID, ex.SubRule = info.Kind, info.RuleID, info.SubRule
	if ex.Kind == "" {
		ex.Kind = RequestHTTP
	}
	ex.Cached, ex.Redirect, ex.Latency, ex.Err = true, false, 0, nil
	r.emit(ex)
}

// Data 记录 TCP、UDP 与 TLS 探测这类没有 HTTP 语义的交换。
func (r *Recorder) Data(ex Exchange, response []byte, start time.Time, err error) {
	if r == nil {
		return
	}
	ex.Latency, ex.Err = time.Since(start), boundedError(err)
	if response != nil {
		sum := sha256.Sum256(response)
		ex.BodyBytes, ex.BodySHA256 = int64(len(response)), hex.EncodeToString(sum[:])
		ex.ResponseBody, ex.BodyTruncated = r.clip(response)
	}
	r.emit(ex)
}

func (r *Recorder) clip(data []byte) ([]byte, bool) {
	if r.limits.MaxBody < 0 {
		return nil, len(data) > 0
	}
	if len(data) > r.limits.MaxBody {
		return append([]byte(nil), data[:r.limits.MaxBody]...), true
	}
	return append([]byte(nil), data...), false
}

// observedBody 在调用方读取正文时计算摘要，关闭时生成最终记录。
type observedBody struct {
	io.ReadCloser
	owner    *Recorder
	exchange Exchange
	start    time.Time
	hash     hash.Hash
	read     int64
	kept     []byte
	eof      bool
	once     sync.Once
	final    *Exchange // 由 owner.mu 保护
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.hash.Write(p[:n])
		b.read += int64(n)
		if limit := b.owner.limits.MaxBody; limit > 0 && len(b.kept) < limit {
			b.kept = append(b.kept, p[:min(n, limit-len(b.kept))]...)
		}
	}
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *observedBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		ex := b.exchange
		ex.Latency = time.Since(b.start)
		ex.BodyBytes = b.read
		ex.BodySHA256 = hex.EncodeToString(b.hash.Sum(nil))
		ex.ResponseBody = b.kept
		ex.BodyTruncated = !b.eof || int64(len(b.kept)) < b.read
		b.kept = nil
		b.owner.mu.Lock()
		b.final = &ex
		b.owner.mu.Unlock()
		b.owner.emit(ex)
	})
	return err
}
