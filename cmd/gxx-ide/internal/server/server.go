// Package server 提供 GXX IDE 的 HTTP server 启动与生命周期管理。
package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/handler"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/router"
)

// Server 把 Gin engine、net.Listener、监听端口一起管理。
//
// 设计：
//   - 端口为 0 时由系统随机分配一个空闲端口，便于 Wails 启动时避免冲突；
//   - Start 返回真实监听端口，前端通过该端口与后端通信；
//   - Shutdown 走 http.Server.Shutdown 优雅停止；
//   - Handler 把 Gin engine 暴露给 Wails AssetServer 作为 fallback handler，
//     这样 webview 内的请求可以走 wails 内嵌 server，无需依赖外部端口。
type Server struct {
	httpServer *http.Server
	handler    http.Handler
	listener   net.Listener
	port       int
	debug      bool
	token      string

	startOnce sync.Once
	stopOnce  sync.Once
}

// New 构造一个 Server，但不会立即启动。
//
//   - port == 0 时使用系统随机端口；
//   - debug=true 时启用 Gin debug 输出，否则 release 模式。
func New(port int, debug bool) (*Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("监听端口 %d 失败: %w", port, err)
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port

	h := handler.NewHandlers()
	token := os.Getenv("GXX_IDE_TOKEN")
	if token == "" {
		token = rand.Text()
	}
	engine := router.Setup(h, debug, token)

	srv := &http.Server{
		Handler:      engine,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return &Server{
		httpServer: srv,
		handler:    engine,
		listener:   listener,
		port:       actualPort,
		debug:      debug,
		token:      token,
	}, nil
}

// Port 返回实际监听端口。
func (s *Server) Port() int { return s.port }

// Handler 返回底层 Gin engine，供 Wails AssetServer 作为 fallback handler 使用，
// 这样 webview 中 fetch("/api/...") 不再依赖独立监听的 9527 端口。
func (s *Server) Handler() http.Handler { return s.handler }

// Start 在调用方 goroutine 中启动 Serve，阻塞直至错误。
// 建议在独立 goroutine 中调用，由 Wails 主 goroutine 持有 UI。
func (s *Server) Start() error {
	var err error
	s.startOnce.Do(func() {
		err = s.httpServer.Serve(s.listener)
		if err == http.ErrServerClosed {
			err = nil
		}
	})
	return err
}

// Shutdown 优雅关闭 server，超过 timeout 强制退出。
func (s *Server) Shutdown(timeout time.Duration) error {
	var shutErr error
	s.stopOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		shutErr = s.httpServer.Shutdown(ctx)
		if shutErr != nil {
			_ = s.httpServer.Close()
		}
	})
	return shutErr
}

// Token 返回当前进程的访问令牌，仅供本机 Wails 绑定传递。
func (s *Server) Token() string { return s.token }
