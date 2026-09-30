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
	"strings"
	"time"

	"github.com/chainreactors/proxyclient"

	"io"
	"net"
	"net/url"
)

const (
	DefaultNetwork      = "tcp"
	DefaultDialTimeout  = 5 * time.Second
	DefaultWriteTimeout = 5 * time.Second
	DefaultReadTimeout  = 5 * time.Second
	DefaultRetryDelay   = 2 * time.Second
	DefaultReadSize     = 2048
	DefaultMaxRetries   = 3
)

// TcpOrUdpConfig 配置结构体
type TcpOrUdpConfig struct {
	VerifyTLS    bool          // 是否校验 TLS 证书；默认保留扫描兼容性。
	Network      string        // 网络类型，TCP 或 UDP
	MaxRetries   int           // 最大重试次数
	ReadSize     int           // 读取数据的缓冲区大小
	DialTimeout  time.Duration // 连接超时时间
	WriteTimeout time.Duration // 写入超时时间
	ReadTimeout  time.Duration // 读取超时时间
	RetryDelay   time.Duration // 重试延迟时间
	ProxyURL     string        // 代理URL
	IsLts        bool          // 是否发送LTS请求
	ServerName   string        // ServerName对tls请求的配置
}

// Client 客户端结构体
type Client struct {
	ctx     context.Context
	stop    func() bool
	address string
	conn    net.Conn
	conf    TcpOrUdpConfig
}

// parseAddress 解析地址，确保包含端口号
func parseAddress(address string) string {
	if strings.Contains(address, "://") {
		if u, err := url.Parse(address); err == nil && u.Hostname() != "" {
			port := u.Port()
			if port == "" {
				port = "80"
				if u.Scheme == "https" || u.Scheme == "tls" {
					port = "443"
				}
			}
			return net.JoinHostPort(u.Hostname(), port)
		}
	}
	// 保留已有端口，并兼容不带端口的 IPv6 地址。
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}

	return net.JoinHostPort(strings.Trim(address, "[]"), "80")
}

// NewClientContext 将连接、TLS 握手和读写统一绑定到调用方的生命周期。
func NewClientContext(ctx context.Context, address string, conf TcpOrUdpConfig) (*Client, error) {
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
	c := &Client{address: parseAddress(address), conf: conf, ctx: ctx}
	var err error
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
	conn, err := DialContext(c.ctx, c.network(), c.address, c.conf.ProxyURL, c.dialTimeout(), c.conf.IsLts, c.conf.ServerName, !c.conf.VerifyTLS)
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
func DialContext(ctx context.Context, network, address, proxyURL string, timeout time.Duration, useTLS bool, serverName string, insecure bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := (&net.Dialer{Timeout: timeout}).DialContext
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		proxy, err := proxyclient.NewClient(u)
		if err != nil {
			return nil, err
		}
		dial = proxy.DialContext
	}
	conn, err := dial(dialCtx, network, address)
	if err != nil {
		return nil, err
	}
	if useTLS {
		secure := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure})
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
	_, err := c.conn.Write(data)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return c.retryWrite(data)
		}
		return err
	}
	return nil
}

// Receive 接收数据
func (c *Client) Receive() ([]byte, error) {
	if c.conn == nil {
		return nil, errors.New("connection is not established")
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout()))
	buf := make([]byte, c.readSize())
	n, err := c.conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err != nil {
		return c.retryRead(buf)
	}
	return buf[:n], nil
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

// retryWrite 重试写入数据
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
		if _, err = c.conn.Write(data); err == nil {
			return nil
		}
	}
	return fmt.Errorf("重试写入失败: %w", err)
}
func (c *Client) retryRead(buf []byte) ([]byte, error) {
	var err error
	for i := 0; i < c.maxRetries(); i++ {
		if err = c.waitRetry(); err != nil {
			return nil, err
		}
		if err = c.reconnect(); err != nil {
			continue
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(c.readTimeout()))
		n, readErr := c.conn.Read(buf)
		err = readErr
		if n > 0 {
			return buf[:n], nil
		}
	}
	if err == nil {
		err = io.EOF
	}
	return nil, fmt.Errorf("重试读取失败: %w", err)
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
