/*
  - Package request
    @Author: zhizhuo
    @IDE：GoLand
    @File: network.go
    @Date: 2025/1/8 下午2:39*
*/
package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	DefaultNetwork      = "tcp"
	DefaultDialTimeout  = 5 * time.Second
	DefaultWriteTimeout = 5 * time.Second
	DefaultReadTimeout  = 5 * time.Second
	DefaultRetryDelay   = 2 * time.Second
	DefaultReadSize     = 2048
	DefaultMaxRetries   = 3

	// TCP 收到首段数据后等待后续数据的空闲时间范围。未显式配置时取首段到达
	// 耗时的两倍并限制在该范围内：往返越慢的连接，分段之间的间隔通常也越长。
	MinReadIdle = 100 * time.Millisecond
	MaxReadIdle = time.Second
)

// TcpOrUdpConfig 配置结构体。是否进行 TLS 握手由连接地址决定（见 ParseEndpoint）。
type TcpOrUdpConfig struct {
	VerifyTLS    bool          // 是否校验 TLS 证书；默认保留扫描兼容性。
	Network      string        // 网络类型，TCP 或 UDP
	MaxRetries   int           // 最大重试次数
	ReadSize     int           // 读取数据的缓冲区大小
	DialTimeout  time.Duration // 连接超时时间
	WriteTimeout time.Duration // 写入超时时间
	ReadTimeout  time.Duration // 单次接收的总时长上限
	ReadIdle     time.Duration // TCP 收到数据后等待后续数据的空闲时间；0 表示自适应
	RetryDelay   time.Duration // 重试延迟时间
	ProxyURL     string        // 代理URL
	ServerName   string        // TLS ServerName；为空时使用连接地址中的主机
}

// Client 客户端结构体
type Client struct {
	ctx      context.Context
	stop     func() bool
	address  string
	endpoint Endpoint
	conn     net.Conn
	conf     TcpOrUdpConfig
}

// NewClientContext 将连接、TLS 握手和读写统一绑定到调用方的生命周期。
func NewClientContext(ctx context.Context, address string, conf TcpOrUdpConfig) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conf.DialTimeout <= 0 {
		conf.DialTimeout = DefaultDialTimeout
	}
	if conf.RetryDelay <= 0 {
		conf.RetryDelay = DefaultRetryDelay
	}
	if conf.MaxRetries <= 0 {
		conf.MaxRetries = DefaultMaxRetries
	}
	if conf.Network == "" {
		conf.Network = DefaultNetwork
	}
	conf.Network = strings.ToLower(strings.TrimSpace(conf.Network))
	if conf.ReadTimeout < 0 || conf.WriteTimeout < 0 || conf.ReadIdle < 0 {
		return nil, errors.New("读写超时不能为负数")
	}
	endpoint, err := ParseEndpoint(address, conf.Network)
	if err != nil {
		return nil, err
	}
	if conf.ServerName == "" {
		conf.ServerName = endpoint.Host
	}
	c := &Client{address: endpoint.Address(), endpoint: endpoint, conf: conf, ctx: ctx}
	for i := 0; i < c.maxRetries(); i++ {
		if err = c.reconnect(); err == nil {
			return c, nil
		}
		if i+1 < c.maxRetries() {
			if waitErr := c.waitRetry(); waitErr != nil {
				return nil, waitErr
			}
		}
	}
	return nil, err
}

func (c *Client) reconnect() error {
	if c.stop != nil {
		c.stop()
	}
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	conn, err := DialContext(c.ctx, c.network(), c.address, c.conf.ProxyURL, c.dialTimeout(), c.endpoint.TLS, c.conf.ServerName, !c.conf.VerifyTLS)
	if err != nil {
		return err
	}
	c.conn = conn
	c.stop = context.AfterFunc(c.ctx, func() { _ = conn.Close() })
	return nil
}
func (c *Client) waitRetry() error {
	timer := time.NewTimer(c.retryTimeout())
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

// DialContext 保持代理、取消和 TLS 策略在初次连接与重试时一致。
// 支持 TCP/UDP 经 HTTP、SOCKS5、SOCKS5h 代理（UDP 仅 SOCKS5 系）。
func DialContext(ctx context.Context, network, address, proxyURL string, timeout time.Duration, useTLS bool, serverName string, insecure bool) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if useTLS && isUDPNetwork(network) {
		return nil, errors.New("UDP 不支持 TLS")
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	proxy, err := normalizeProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialThroughProxy(dialCtx, network, address, proxy, timeout)
	if err != nil {
		return nil, err
	}
	if useTLS {
		// 与 HTTP 路径统一的扫描 TLS 策略：最低 TLS 1.0 + 完整套件，兼容老旧设备。
		secure := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS10, CipherSuites: scannerCipherSuites()})
		if err = secure.HandshakeContext(dialCtx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = secure
	}
	return conn, nil
}

// Send 发送数据
func (c *Client) Send(data []byte) error {
	if c.conn == nil {
		return errors.New("connection is not established")
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout()))
	n, err := c.conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return c.retryWrite(data)
		}
		return err
	}
	return nil
}

// Receive 接收数据。UDP 每次接收一个数据报；TCP 读取到缓冲区上限、对端关闭、
// 空闲超时或总时长上限为止。
//
// TCP 响应可能分多段到达，而多数服务发完响应后不会关闭连接。收到首段数据后，
// 每次读取最多再等待一个空闲时间：配置了 ReadIdle 时使用配置值，否则取首段
// 到达耗时的两倍并限制在 [MinReadIdle, MaxReadIdle] 内。总时长始终受 ReadTimeout
// 约束，空闲等待只会让接收提前结束，不会越过总截止时间。
func (c *Client) Receive() ([]byte, error) {
	if c.conn == nil {
		return nil, errors.New("connection is not established")
	}

	buf := make([]byte, c.readSize())
	if isUDPNetwork(c.network()) {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout()))
		n, err := c.conn.Read(buf)
		if n > 0 {
			return buf[:n], nil
		}
		return nil, err
	}

	start := time.Now()
	deadline := start.Add(c.readTimeout())
	idle := c.conf.ReadIdle
	offset := 0
	for offset < len(buf) {
		now := time.Now()
		if !now.Before(deadline) {
			break
		}
		next := deadline
		if offset > 0 {
			if candidate := now.Add(idle); candidate.Before(deadline) {
				next = candidate
			}
		}
		_ = c.conn.SetReadDeadline(next)
		n, err := c.conn.Read(buf[offset:])
		if offset == 0 && n > 0 && idle <= 0 {
			idle = min(max(2*time.Since(start), MinReadIdle), MaxReadIdle)
		}
		offset += n
		if err != nil {
			if offset > 0 {
				return buf[:offset], nil
			}
			return nil, err
		}
		if n == 0 {
			break
		}
	}
	return buf[:offset], nil
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.stop != nil {
		c.stop()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// retryWrite 重试写入数据；重连后会重新发送完整负载。
func (c *Client) retryWrite(data []byte) error {
	var err error
	for i := 0; i < c.maxRetries(); i++ {
		if err = c.waitRetry(); err != nil {
			return err
		}
		if err = c.reconnect(); err != nil {
			continue
		}
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout()))
		var n int
		if n, err = c.conn.Write(data); err == nil {
			if n == len(data) {
				return nil
			}
			err = io.ErrShortWrite
		}
	}
	return fmt.Errorf("重试写入失败: %w", err)
}

func (c *Client) network() string {
	if len(c.conf.Network) > 0 {
		return c.conf.Network
	}
	return DefaultNetwork
}

func (c *Client) dialTimeout() time.Duration {
	if c.conf.DialTimeout != 0 {
		return c.conf.DialTimeout
	}
	return DefaultDialTimeout
}

func (c *Client) writeTimeout() time.Duration {
	if c.conf.WriteTimeout != 0 {
		return c.conf.WriteTimeout
	}
	return DefaultWriteTimeout
}

func (c *Client) readTimeout() time.Duration {
	if c.conf.ReadTimeout != 0 {
		return c.conf.ReadTimeout
	}
	return DefaultReadTimeout
}

func (c *Client) retryTimeout() time.Duration {
	if c.conf.RetryDelay != 0 {
		return c.conf.RetryDelay
	}
	return DefaultRetryDelay
}

func (c *Client) maxRetries() int {
	if c.conf.MaxRetries != 0 {
		return c.conf.MaxRetries
	}
	return DefaultMaxRetries
}

func (c *Client) readSize() int {
	if c.conf.ReadSize > 0 && int64(c.conf.ReadSize) <= MaxDefaultBody {
		return c.conf.ReadSize
	}
	if int64(c.conf.ReadSize) > MaxDefaultBody {
		return int(MaxDefaultBody)
	}
	return DefaultReadSize
}
