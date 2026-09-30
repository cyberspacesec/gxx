/*
GXX IDE - 指纹规则可视化开发工具。

启动后台 Gin HTTP server 提供 RESTful API（含 Swagger UI），
前台 Wails app 把内置 webview 指向后端端口，从而既能本地 GUI 使用，
又能让外部工具直接通过 HTTP 调用后端能力。

技术栈：Wails v2 + Gin + Swag + Vue 3 + Vite + TypeScript + Monaco Editor。

@title           GXX IDE API
@version         1.0
@description     GXX 指纹规则编辑器 HTTP API：提供请求测试、YAML 校验、指纹运行、CEL 调试、指纹库 CRUD 能力。
@termsOfService  https://github.com/

@contact.name    zhizhuo
@contact.url     https://github.com/

@license.name    MIT
@host            127.0.0.1
@BasePath        /
@schemes         http
@securityDefinitions.apikey ApiToken
@in header
@name Authorization
@description 输入 Bearer 和当前会话令牌。
*/
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	docs "github.com/cyberspacesec/gxx/cmd/gxx-ide/docs"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/server"
)

// APISession 将令牌通过 Wails 原生绑定交给当前桌面窗口。
type APISession struct{ server *server.Server }

func (s *APISession) Token() string { return s.server.Token() }

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	port := flag.Int("port", 9527, "HTTP server 端口；默认 9527，可通过 GXX_IDE_PORT 环境变量覆盖")
	if v := os.Getenv("GXX_IDE_PORT"); v != "" {
		fmt.Sscanf(v, "%d", port)
	}
	debug := flag.Bool("debug", false, "启用 Gin debug 模式")
	headless := flag.Bool("headless", false, "仅启动后端 HTTP server（不打开 Wails 窗口），适合纯 API 调用 / docker 场景")
	flag.Parse()

	srv, err := server.New(*port, *debug)
	if err != nil {
		log.Fatalf("启动 HTTP server 失败: %v", err)
	}

	// 把动态分配到的端口写入 docs.SwaggerInfo，让 Swagger UI 中 try-it-out 指向正确地址
	docs.SwaggerInfo.Host = fmt.Sprintf("127.0.0.1:%d", srv.Port())

	// 同步真实端口到环境变量，便于第三方进程探测
	_ = os.Setenv("GXX_IDE_API_PORT", fmt.Sprintf("%d", srv.Port()))

	var (
		wg   sync.WaitGroup
		stop = make(chan struct{})
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("[gxx-ide] HTTP server 启动: http://127.0.0.1:%d  Swagger: http://127.0.0.1:%d/swagger/index.html", srv.Port(), srv.Port())
		if err := srv.Start(); err != nil {
			log.Printf("[gxx-ide] HTTP server 异常退出: %v", err)
		}
		close(stop)
	}()

	if *headless {
		signalCtx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancelSignal()
		if os.Getenv("GXX_IDE_TOKEN") == "" {
			f, e := os.CreateTemp("", "gxx-ide-token-*")
			if e != nil {
				log.Fatalf("保存访问令牌失败: %v", e)
			}
			_ = f.Chmod(0o600)
			_, e = f.WriteString(srv.Token())
			_ = f.Close()
			if e != nil {
				log.Fatal(e)
			}
			defer os.Remove(f.Name())
			log.Printf("API 访问令牌文件: %s", f.Name())
		}
		select {
		case <-stop:
		case <-signalCtx.Done():
			_ = srv.Shutdown(5 * time.Second)
			wg.Wait()
		}
		return
	}

	// 启动 Wails app（前台）；当 Wails 退出时关闭 HTTP server。
	// AssetServer.Handler 注入 Gin engine：
	//   - 静态资源（HTML/JS/CSS/图片）由 wails 从 embed.FS 提供
	//   - /api/v1/* /swagger/* /healthz 在 embed.FS 中不存在 → fallback 到 Gin
	// 这样 webview 内的 fetch 全部走相对路径，不再依赖独立监听的 9527 端口，
	// 即便 -port=0（系统随机端口）或端口冲突也能正常工作。
	runErr := wails.Run(&options.App{
		Title:  "GXX 指纹规则编辑器",
		Bind:   []interface{}{&APISession{server: srv}},
		Width:  1440,
		Height: 900,
		AssetServer: &assetserver.Options{
			Assets:  assets,
			Handler: srv.Handler(),
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup: func(_ context.Context) {
			log.Printf("[gxx-ide] Wails GUI 已启动，后端 API: http://127.0.0.1:%d", srv.Port())
		},
		OnShutdown: func(_ context.Context) {
			_ = srv.Shutdown(5 * time.Second)
		},
	})
	if runErr != nil {
		log.Printf("[gxx-ide] Wails 退出: %v", runErr)
		_ = srv.Shutdown(5 * time.Second)
	}
	wg.Wait()
}
