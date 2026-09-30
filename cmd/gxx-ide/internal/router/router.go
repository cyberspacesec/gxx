// Package router 统一注册 GXX IDE 的全部 HTTP 路由。
package router

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/handler"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/middleware"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
)

// Setup 创建一个完整配置好的 *gin.Engine。
//
//   - 全局中间件：logger / recovery / cors
//   - /healthz：健康检查
//   - /swagger/*：Swagger UI
//   - /api/v1/*：业务路由
func Setup(h *handler.Handlers, debug bool, tokens ...string) *gin.Engine {
	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(middleware.Logger(), middleware.Recovery(), middleware.CORS())

	notFound, notAllowed := middleware.NoMethodOrRoute()
	r.NoRoute(notFound)
	r.NoMethod(notAllowed)

	r.GET("/healthz", func(c *gin.Context) {
		response.OK(c, gin.H{"status": "ok"})
	})
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	token := ""
	if len(tokens) > 0 {
		token = tokens[0]
	}
	api := r.Group("/api/v1", middleware.Authorize(token))
	{
		req := api.Group("/request")
		req.POST("/send", h.Request.Send)

		yml := api.Group("/yaml")
		yml.POST("/validate", h.YAML.Validate)

		finger := api.Group("/finger")
		finger.POST("/run", h.Finger.Run)

		cel := api.Group("/cel")
		cel.POST("/evaluate", h.Finger.EvaluateCEL)

		lib := api.Group("/library")
		{
			lib.GET("/default", h.Library.DefaultDir)
			lib.GET("/list", h.Library.List)
			lib.GET("/load", h.Library.Load)
			lib.POST("/save", h.Library.Save)
			lib.DELETE("/delete", h.Library.Delete)
		}
	}

	return r
}
