package network

import (
	"bytes"
	"crypto/tls"
	"net"
	"sync"
)

// 响应头顺序的记录上限：只记录名称，超出部分不再记录。
const (
	maxHeaderNames      = 256
	maxHeaderNameBytes  = 256
	maxHeaderBlockBytes = 1 << 20
)

// trackedConn 包装 Transport 使用的连接（HTTPS 时位于 TLS 之上），记录每个响应的
// 响应头名称顺序，TLS 连接另外保存握手摘要。只观察 Transport 本来就会读写的字节。
type trackedConn struct {
	net.Conn
	tls *connTLS

	mu      sync.Mutex
	sniffer headerSniffer
}

type connTLS struct {
	state tls.ConnectionState
	info  TLSInfo
}

func newTrackedConn(conn net.Conn, secure *tls.Conn, recorder *helloRecorder) *trackedConn {
	tracked := &trackedConn{Conn: conn}
	if secure != nil {
		state := secure.ConnectionState()
		var hello ServerHello
		var found bool
		if recorder != nil {
			hello, found = recorder.serverHello()
		}
		tracked.tls = &connTLS{state: state, info: tlsSummary(&state, hello, found)}
	}
	return tracked
}

// Write 标记一个新请求：其后读到的首个最终响应头块属于该请求。
func (c *trackedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.sniffer.begin()
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.sniffer.feed(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

// takeHeaderOrder 返回最近一个已读完的最终响应头块的名称顺序，并清除记录。
// HTTP/1.x 同一连接上一次只有一个请求在途，RoundTrip 返回时该块属于本次请求。
func (c *trackedConn) takeHeaderOrder() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	order := c.sniffer.done
	c.sniffer.done = nil
	return order
}

// headerSniffer 逐字节解析 HTTP/1.x 响应头块，只保留名称。1xx 中间响应跳过。
type headerSniffer struct {
	active   bool
	started  bool // 已读到状态行
	informal bool // 当前块是 1xx 响应
	line     []byte
	names    []string
	bytes    int
	done     []string
}

func (s *headerSniffer) begin() {
	if s.active {
		return
	}
	*s = headerSniffer{active: true, line: s.line[:0]}
}

func (s *headerSniffer) feed(data []byte) {
	for s.active && len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		chunk := data
		if end >= 0 {
			chunk = data[:end]
			data = data[end+1:]
			s.bytes++
		} else {
			data = nil
		}
		s.bytes += len(chunk)
		// 只需要冒号之前的名称，过长的行截断保存。
		if room := maxHeaderNameBytes - len(s.line); room > 0 {
			s.line = append(s.line, chunk[:min(room, len(chunk))]...)
		}
		if end < 0 {
			if s.bytes > maxHeaderBlockBytes {
				s.finish()
			}
			continue
		}
		s.line = bytes.TrimSuffix(s.line, []byte("\r"))
		s.endLine()
		s.line = s.line[:0]
		if s.bytes > maxHeaderBlockBytes {
			s.finish()
		}
	}
}

func (s *headerSniffer) endLine() {
	line := s.line
	if !s.started {
		// 状态行：不是 HTTP 报文时不再解析。
		if !bytes.HasPrefix(line, []byte("HTTP/")) {
			s.active = false
			return
		}
		s.started = true
		if space := bytes.IndexByte(line, ' '); space >= 0 && len(line) > space+1 && line[space+1] == '1' {
			s.informal = true
		}
		return
	}
	if len(line) == 0 {
		if s.informal {
			s.started, s.informal, s.names = false, false, nil
			return
		}
		s.finish()
		return
	}
	if line[0] == ' ' || line[0] == '\t' {
		return
	}
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 || len(s.names) >= maxHeaderNames {
		return
	}
	s.names = append(s.names, string(bytes.TrimRight(line[:colon], " \t")))
}

func (s *headerSniffer) finish() {
	s.done = s.names
	if s.done == nil {
		s.done = []string{}
	}
	s.active, s.names = false, nil
}
