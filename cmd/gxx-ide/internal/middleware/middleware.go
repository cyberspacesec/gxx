// Package middleware 提供 GXX IDE HTTP server 的通用中间件。
package middleware

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
)

// Logger 输出每个请求的 method / path / status / latency。
// 简化版本，便于排查问题，不引入第三方日志库。
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		fmt.Printf("[GIN] %s %s %d %s\n",
			c.Request.Method, c.Request.URL.Path, c.Writer.Status(), latency)
	}
}

// Recovery 拦截 panic 并返回标准化 500 响应。
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				response.ServerError(c, fmt.Sprintf("internal panic: %v", r))
			}
		}()
		c.Next()
	}
}

// CORS 允许 Wails 与本机开发页面，拒绝来自其他网站的浏览器请求。
func CORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			return origin == "wails://wails.localhost" || ((u.Scheme == "http" || u.Scheme == "https") && (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "wails.localhost"))
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	})
}

// NoMethodOrRoute 把 404 / 405 统一封装到 {code, message} 结构。
func NoMethodOrRoute() (gin.HandlerFunc, gin.HandlerFunc) {
	notFound := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusNotFound, response.APIResponse{
			Code:    http.StatusNotFound,
			Message: fmt.Sprintf("路径不存在: %s", c.Request.URL.Path),
		})
	}
	notAllowed := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, response.APIResponse{
			Code:    http.StatusMethodNotAllowed,
			Message: fmt.Sprintf("方法不允许: %s %s", c.Request.Method, c.Request.URL.Path),
		})
	}
	return notFound, notAllowed
}

// Authorize 校验实例令牌并阻止通过非本机 Host 访问文件接口。
func Authorize(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "wails.localhost" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		provided := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, response.APIResponse{Code: http.StatusUnauthorized, Message: "访问令牌无效"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<20)
		c.Next()
	}
}
