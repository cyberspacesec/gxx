/*
Package sdk 输出写入器（OutputWriter）。

Writer 是 SDK 自有的输出抽象，对每个完成扫描的 *TargetResult 执行落盘 / 转发动作。
所有内置实现都是实例化的：每个 Engine 通过 Option 注入自己的 Writer，
不依赖任何包级全局状态，多 Engine 可在同进程并发使用而互不污染。

可通过以下 Option 启用：

	sdk.WithOutputFile("results.json", "json")
	sdk.WithSockOutputFile("/tmp/gxx.sock")
	sdk.WithWriter(myCustomWriter) // 自行实现 Writer 接口

多个 Option 会被 MultiWriter 自动合并，写入失败只记录日志，不影响扫描主流程。
*/
package sdk

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OutputFormat 列举 FileWriter 支持的写出格式。
type OutputFormat string

const (
	// FormatTXT 人类可读文本，单条记录用分隔线拼接。
	FormatTXT OutputFormat = "txt"
	// FormatCSV 标准 CSV，带 UTF-8 BOM 表头。
	FormatCSV OutputFormat = "csv"
	// FormatJSON 每行一条 JSON Lines。
	FormatJSON OutputFormat = "json"
)

// normalize 把外部传入的格式字符串归一为内部枚举；未知值回退到 txt。
func (f OutputFormat) normalize() OutputFormat {
	switch strings.ToLower(string(f)) {
	case string(FormatCSV):
		return FormatCSV
	case string(FormatJSON):
		return FormatJSON
	default:
		return FormatTXT
	}
}

// Writer 是 SDK 把 *TargetResult 持久化或转发出去的抽象。
//
// 内置实现：FileWriter / SockWriter / MultiWriter / NopWriter。
// 调用方也可自行实现该接口（如对接 Kafka、Webhook 等），并通过
// sdk.WithWriter(w) 注入到 Engine。
//
// Write 必须满足以下并发约束：
//   - 同一实例可能被多 goroutine 并发调用，实现需自行保证线程安全；
//   - Write 收到 nil 时必须直接返回 nil，不得 panic；
//   - 即便返回 error，Engine 也只会记录日志，不会终止扫描。
//
// Close 在 Engine.Close 中被调用，实现应释放底层资源并 flush 缓冲；
// 重复调用必须幂等。
type Writer interface {
	Write(ctx context.Context, result *TargetResult) error
	Close() error
}

// nopWriter 是 Writer 的零值实现，所有方法均无副作用。
type nopWriter struct{}

// NopWriter 返回不执行任何写出动作的 Writer，常用于禁用输出。
func NopWriter() Writer { return nopWriter{} }

// Write 实现 Writer 接口，忽略所有输入。
func (nopWriter) Write(context.Context, *TargetResult) error { return nil }

// Close 实现 Writer 接口，无需释放任何资源。
func (nopWriter) Close() error { return nil }

// MultiWriter 把多个 Writer 串行组合，写入按注册顺序依次触发，
// 单个 writer 错误会被收集到 errors.Join 中返回，不影响后续 writer。
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter 用一组 Writer 构造 MultiWriter，nil 元素会被忽略。
func NewMultiWriter(writers ...Writer) *MultiWriter {
	out := make([]Writer, 0, len(writers))
	for _, w := range writers {
		if w == nil {
			continue
		}
		out = append(out, w)
	}
	return &MultiWriter{writers: out}
}

// Write 依次调用底层 Writer.Write，收集全部 error 后统一返回。
func (m *MultiWriter) Write(ctx context.Context, result *TargetResult) error {
	if m == nil || result == nil {
		return nil
	}
	var errs []error
	for _, w := range m.writers {
		if err := w.Write(ctx, result); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close 关闭所有底层 Writer 并收集错误。
func (m *MultiWriter) Close() error {
	if m == nil {
		return nil
	}
	var errs []error
	for _, w := range m.writers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// fileWriter 把扫描结果写入本地文件，三种格式独立处理。
//
// 设计要点：
//   - 实例化字段（file/format/mu/csvWriter/queue）取代旧的 output 包级全局变量，
//     多 Engine 可同时持有各自的 fileWriter，互不影响；
//   - queue 容量 = fileQueueSize 的异步通道，loop 在独立 goroutine 中串行执行
//     格式化 + 落盘，URL worker 不再竞争文件锁；
//   - Write 热路径仅做一次 atomic.Load + 非阻塞 select-send，无 mutex；
//     队列满或已停止接收时回退同步 writeSync，writeSync 通过 mu 保护文件操作；
//   - Close 设 closing 标志 → close(done) → loop drain 残余 → flush CSV → 关闭文件，
//     重复调用幂等。
type fileWriter struct {
	admission sync.RWMutex
	writeErr  error
	path      string
	format    OutputFormat

	mu        sync.Mutex
	file      *os.File
	csvWriter *csv.Writer

	queue     chan *TargetResult
	done      chan struct{}
	closing   atomic.Bool
	loopWG    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// fileQueueSize 与 utils/output 异步写入器保持一致的经验值：
// 与 URL 工作池容量 × 16 同量级，能缓冲短时突发又不至于撑爆内存。
const fileQueueSize = 1024

// NewFileWriter 创建一个把 *TargetResult 写到本地文件的 Writer。
//
//   - path:   目标文件路径，父目录会被自动创建；空字符串时返回 NopWriter；
//   - format: txt / csv / json，未知值回退到 txt。
//
// 已存在的文件会以追加模式打开（CSV 例外：仅在新建时写入 UTF-8 BOM + 表头）。
func NewFileWriter(path string, format OutputFormat) (Writer, error) {
	if strings.TrimSpace(path) == "" {
		return NopWriter(), nil
	}
	normalized := format.normalize()

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("%w: create output dir: %v", ErrInvalidOption, err)
		}
	}

	exists := false
	if _, err := os.Stat(path); err == nil {
		exists = true
	}

	var (
		file *os.File
		err  error
	)
	if normalized == FormatCSV && !exists {
		file, err = os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("%w: create output file: %v", ErrInvalidOption, err)
		}
		if _, werr := file.Write([]byte{0xEF, 0xBB, 0xBF}); werr != nil {
			_ = file.Close()
			return nil, fmt.Errorf("%w: write BOM: %v", ErrInvalidOption, werr)
		}
	} else {
		file, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("%w: open output file: %v", ErrInvalidOption, err)
		}
	}

	fw := &fileWriter{
		path:   path,
		format: normalized,
		file:   file,
		queue:  make(chan *TargetResult, fileQueueSize),
		done:   make(chan struct{}),
	}
	if normalized == FormatCSV {
		fw.csvWriter = csv.NewWriter(file)
		if !exists {
			if err := fw.writeCSVHeader(); err != nil {
				_ = file.Close()
				return nil, fmt.Errorf("%w: write CSV header: %v", ErrInvalidOption, err)
			}
		}
	} else if normalized == FormatTXT && !exists {
		if err := fw.writeTXTHeader(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("%w: write txt header: %v", ErrInvalidOption, err)
		}
	}

	fw.loopWG.Add(1)
	go fw.loop()
	return fw, nil
}

// Write 把结果投递到异步队列，队列满或 Writer 正在关闭时回退到同步路径。
// 热路径完全无锁：只做一次 atomic.Load + 非阻塞 select-send。
func (w *fileWriter) Write(ctx context.Context, result *TargetResult) error {
	if w == nil || result == nil {
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	w.admission.RLock()
	defer w.admission.RUnlock()
	if w.closing.Load() {
		return os.ErrClosed
	}
	result = cloneTargetResult(result)
	if !w.closing.Load() {
		select {
		case w.queue <- result:
			return nil
		default:
		}
	}
	return w.writeSync(result)
}

// Close 停止异步 writer，flush CSV 缓冲后关闭文件句柄；重复调用幂等。
func (w *fileWriter) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		w.admission.Lock()
		w.closing.Store(true)
		close(w.done)
		w.admission.Unlock()
		w.loopWG.Wait()

		w.mu.Lock()
		defer w.mu.Unlock()
		if w.csvWriter != nil {
			w.csvWriter.Flush()
			w.closeErr = errors.Join(w.closeErr, w.csvWriter.Error())
		}
		if w.file != nil {
			w.closeErr = errors.Join(w.closeErr, w.file.Close())
			w.file = nil
		}
		w.closeErr = errors.Join(w.closeErr, w.writeErr)
	})
	return w.closeErr
}

// loop 串行消费 queue 中的结果，done 关闭时进入 drain 阶段。
func (w *fileWriter) loop() {
	defer w.loopWG.Done()
	for {
		select {
		case r := <-w.queue:
			if err := w.writeSync(r); err != nil {
				defaultErrorLogger("文件输出写入失败: %v", err)
			}
		case <-w.done:
			w.drain()
			return
		}
	}
}

func (w *fileWriter) drain() {
	for {
		select {
		case r := <-w.queue:
			if err := w.writeSync(r); err != nil {
				defaultErrorLogger("文件输出 drain 阶段写入失败: %v", err)
			}
		default:
			return
		}
	}
}

func (w *fileWriter) writeSync(result *TargetResult) (err error) {
	if result == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if err != nil && w.writeErr == nil {
			w.writeErr = err
		}
	}()
	if w.file == nil {
		return os.ErrClosed
	}
	switch w.format {
	case FormatJSON:
		return w.writeJSON(result)
	case FormatCSV:
		return w.writeCSV(result)
	default:
		return w.writeTXT(result)
	}
}

func (w *fileWriter) writeJSON(result *TargetResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	if _, err := w.file.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	return nil
}

func (w *fileWriter) writeCSV(result *TargetResult) error {
	if w.csvWriter == nil {
		w.csvWriter = csv.NewWriter(w.file)
	}
	row := buildCSVRow(result)
	if err := w.csvWriter.Write(row); err != nil {
		return fmt.Errorf("write csv row: %w", err)
	}
	w.csvWriter.Flush()
	return w.csvWriter.Error()
}

func (w *fileWriter) writeTXT(result *TargetResult) error {
	var sb strings.Builder
	sb.Grow(512)
	sb.WriteString("URL: ")
	sb.WriteString(result.URL)
	sb.WriteString("\n状态码: ")
	fmt.Fprintf(&sb, "%d", result.StatusCode)
	sb.WriteString("\n标题: ")
	sb.WriteString(result.Title)
	if result.Server != nil {
		sb.WriteString("\n服务器: ")
		sb.WriteString(result.Server.ServerType)
	}
	if strings.TrimSpace(result.ICP) != "" {
		sb.WriteString("\nICP备案号: ")
		sb.WriteString(strings.TrimSpace(result.ICP))
	}
	if len(result.Matches) > 0 {
		sb.WriteString("\n匹配指纹: ")
		names := make([]string, 0, len(result.Matches))
		for _, m := range result.Matches {
			names = append(names, m.Info.Name)
		}
		sb.WriteString(strings.Join(names, ", "))
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("-", 80))
	sb.WriteString("\n")
	if _, err := io.WriteString(w.file, sb.String()); err != nil {
		return fmt.Errorf("write txt: %w", err)
	}
	return nil
}

func (w *fileWriter) writeCSVHeader() error {
	if w.csvWriter == nil {
		w.csvWriter = csv.NewWriter(w.file)
	}
	if err := w.csvWriter.Write(csvHeader()); err != nil {
		return err
	}
	w.csvWriter.Flush()
	return w.csvWriter.Error()
}

func (w *fileWriter) writeTXTHeader() error {
	const sep = "============================================================\n"
	if _, err := io.WriteString(w.file, sep); err != nil {
		return err
	}
	if _, err := io.WriteString(w.file, "GXX Scan Result\n"); err != nil {
		return err
	}
	_, err := io.WriteString(w.file, sep)
	return err
}

// csvHeader 返回 CSV 表头字段，与 buildCSVRow 顺序保持一致。
func csvHeader() []string {
	return []string{"URL", "状态码", "标题", "服务器", "ICP备案号", "指纹ID", "指纹名称", "匹配结果"}
}

// buildCSVRow 把 TargetResult 序列化为 csvHeader 对应的字段顺序。
func buildCSVRow(r *TargetResult) []string {
	server := ""
	if r.Server != nil {
		server = r.Server.ServerType
	}
	ids := make([]string, 0, len(r.Matches))
	names := make([]string, 0, len(r.Matches))
	matched := false
	for _, m := range r.Matches {
		ids = append(ids, m.Info.ID)
		names = append(names, m.Info.Name)
		if m.Result {
			matched = true
		}
	}
	return []string{
		r.URL,
		fmt.Sprintf("%d", r.StatusCode),
		r.Title,
		server,
		strings.TrimSpace(r.ICP),
		"[" + strings.Join(ids, ",") + "]",
		"[" + strings.Join(names, ",") + "]",
		fmt.Sprintf("%v", matched),
	}
}

// sockWriter 通过 Unix domain socket 推送 JSON Lines。
// 每个 accept 到的连接都会被加入 conns 集合，Write 时按顺序广播；
// 连接断开时自动从集合移除，不阻塞扫描主流程。
//
// 生命周期保证：Close 关闭 listener 后等待 acceptLoop 退出（acceptWG），
// 调用方拿到 Close 返回值时后台 goroutine 已完全终止，避免极端场景下泄漏。
type sockWriter struct {
	writeGate chan struct{}
	closedCh  chan struct{}
	closed    atomic.Bool
	path      string
	listener  net.Listener
	acceptWG  sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}

	closeOnce sync.Once
	closeErr  error
}

// NewSockWriter 创建并监听一个 Unix domain socket，
// 把每条扫描结果以 JSON Lines 形式广播到所有客户端连接。
//
// path 为空字符串时返回 NopWriter；socket 文件存在时会先删除再重新创建。
func NewSockWriter(path string) (Writer, error) {
	if strings.TrimSpace(path) == "" {
		return NopWriter(), nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("%w: create sock dir: %v", ErrInvalidOption, err)
		}
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: socket path is not a socket", ErrInvalidOption)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w: listen unix socket: %v", ErrInvalidOption, err)
	}
	sw := &sockWriter{
		writeGate: make(chan struct{}, 1), closedCh: make(chan struct{}),
		path:     path,
		listener: l,
		conns:    make(map[net.Conn]struct{}),
	}
	sw.acceptWG.Add(1)
	go sw.acceptLoop()
	return sw, nil
}

// Write 把 result 序列化为 JSON 并广播到所有活动连接。
// 没有活动连接时直接返回，避免无用的 marshal 与锁竞争。
func (s *sockWriter) Write(ctx context.Context, result *TargetResult) error {
	if s == nil || result == nil {
		return nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if len(s.conns) == 0 {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	data = append(data, '\n')

	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case s.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closedCh:
		return os.ErrClosed
	}
	defer func() { <-s.writeGate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	closed := s.closed.Load()
	s.mu.Unlock()
	if closed {
		return os.ErrClosed
	}
	var errs []error
	for _, c := range conns {
		deadline := time.Now().Add(5 * time.Second)
		if ctx != nil {
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
		}
		_ = c.SetWriteDeadline(deadline)
		cancelDone := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = c.SetWriteDeadline(time.Now()); close(cancelDone) })
		_, err := c.Write(data)
		if !stop() {
			<-cancelDone
		}
		if err != nil {
			_ = c.Close()
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
			errs = append(errs, err)
		}
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(errs...)
}

// Close 停止监听并断开所有连接；重复调用幂等。
//
// 关闭顺序：
//  1. 关闭 listener，acceptLoop 在下次 Accept 失败时退出；
//  2. 等待 acceptWG，确保后台 goroutine 不会继续操作 conns；
//  3. 断开所有现存连接并删除 socket 文件。
func (s *sockWriter) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.closedCh)
		if s.listener != nil {
			s.closeErr = s.listener.Close()
		}
		s.acceptWG.Wait()

		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.conns = make(map[net.Conn]struct{})
		s.mu.Unlock()
		_ = os.Remove(s.path)
	})
	return s.closeErr
}

func (s *sockWriter) acceptLoop() {
	defer s.acceptWG.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			defaultErrorLogger("socket accept 失败: %v", err)
			continue
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

// handleConn 持有连接直到对端断开；本端不消费客户端数据，仅用于探测断连。
func (s *sockWriter) handleConn(conn net.Conn) {
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
	}
}

// defaultErrorLogger 把 Writer 内部错误写到 stderr，与 utils/logger 解耦。
// 这是包级函数变量，便于测试替换（同包可见即可，无需对外暴露）。
func defaultErrorLogger(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[gxx-sdk] "+format+"\n", args...)
}

// cloneTargetResult 为异步消费者创建独立快照，返回值仍归调用方所有。
func cloneTargetResult(r *TargetResult) *TargetResult {
	c := *r
	c.Matches = slices.Clone(r.Matches)
	if r.Server != nil {
		v := *r.Server
		c.Server = &v
	}
	if r.TechStack != nil {
		v := *r.TechStack
		v.WebServers = slices.Clone(v.WebServers)
		v.ReverseProxies = slices.Clone(v.ReverseProxies)
		v.JavaScriptFrameworks = slices.Clone(v.JavaScriptFrameworks)
		v.JavaScriptLibraries = slices.Clone(v.JavaScriptLibraries)
		v.WebFrameworks = slices.Clone(v.WebFrameworks)
		v.StaticSiteGenerator = slices.Clone(v.StaticSiteGenerator)
		v.ProgrammingLanguages = slices.Clone(v.ProgrammingLanguages)
		v.Caching = slices.Clone(v.Caching)
		v.Security = slices.Clone(v.Security)
		v.HostingPanels = slices.Clone(v.HostingPanels)
		v.Other = slices.Clone(v.Other)
		c.TechStack = &v
	}
	c.Certs = slices.Clone(r.Certs)
	for i := range c.Certs {
		v := &c.Certs[i]
		v.Subject = cloneCertName(v.Subject)
		v.Issuer = cloneCertName(v.Issuer)
		v.DNSNames = slices.Clone(v.DNSNames)
		v.EmailAddresses = slices.Clone(v.EmailAddresses)
		v.IPAddresses = slices.Clone(v.IPAddresses)
		v.OCSPServer = slices.Clone(v.OCSPServer)
		v.CRLDistributionPoints = slices.Clone(v.CRLDistributionPoints)
	}
	return &c
}
func cloneCertName(n CertName) CertName {
	n.Organization = slices.Clone(n.Organization)
	n.OrganizationalUnit = slices.Clone(n.OrganizationalUnit)
	n.Country = slices.Clone(n.Country)
	n.Province = slices.Clone(n.Province)
	n.Locality = slices.Clone(n.Locality)
	n.StreetAddress = slices.Clone(n.StreetAddress)
	n.PostalCode = slices.Clone(n.PostalCode)
	return n
}
