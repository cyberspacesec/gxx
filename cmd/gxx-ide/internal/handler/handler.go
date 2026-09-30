// Package handler 提供 GXX IDE HTTP API 的 Gin handler。
//
// 每个 handler 仅做参数解析与统一响应转换，业务逻辑全部委托给 internal/service。
// swagger 注释紧邻函数声明，便于 swag init 一次生成完整 OpenAPI 文档。
package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/service"
)

// Handlers 聚合全部 handler，便于在 router 中按需绑定。
type Handlers struct {
	Request *RequestHandler
	YAML    *YAMLHandler
	Finger  *FingerHandler
	Library *LibraryHandler
}

// NewHandlers 创建 Handlers 实例。
func NewHandlers() *Handlers {
	return &Handlers{
		Request: &RequestHandler{Svc: service.NewRequestService()},
		YAML:    &YAMLHandler{Svc: service.NewYamlService()},
		Finger:  &FingerHandler{Svc: service.NewFingerService()},
		Library: &LibraryHandler{Svc: service.NewLibraryService()},
	}
}

// RequestHandler 处理请求测试 API。
type RequestHandler struct {
	Svc *service.RequestService
}

// Send godoc
//
//	@Summary		发送 HTTP 请求获取响应
//	@Description	支持 URL 参数模式与原始 HTTP raw 报文模式，自动提取标题/Server/证书/favicon hash
//	@Tags			request
//	@Accept			json
//	@Produce		json
//	@Param			payload	body		model.SendRequestInput			true	"请求选项"
//	@Success		200		{object}	response.APIResponse{data=model.SendRequestOutput}
//	@Failure		400		{object}	response.APIResponse
//	@Failure		500		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/request/send [post]
func (h *RequestHandler) Send(c *gin.Context) {
	var in model.SendRequestInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	out, err := h.Svc.Send(c.Request.Context(), &in)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, out)
}

// YAMLHandler 处理 YAML 校验 API。
type YAMLHandler struct {
	Svc *service.YamlService
}

// Validate godoc
//
//	@Summary		校验指纹 YAML 并提取概要
//	@Description	返回是否合法、错误位置（行号 / 列号）以及 finger 概要
//	@Tags			yaml
//	@Accept			json
//	@Produce		json
//	@Param			payload	body		model.ValidateYAMLInput			true	"YAML 内容"
//	@Success		200		{object}	response.APIResponse{data=model.ValidateYAMLOutput}
//	@Failure		400		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/yaml/validate [post]
func (h *YAMLHandler) Validate(c *gin.Context) {
	var in model.ValidateYAMLInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	out := h.Svc.Validate(in.Content)
	response.OK(c, out)
}

// FingerHandler 处理指纹运行与 CEL 调试 API。
type FingerHandler struct {
	Svc *service.FingerService
}

// Run godoc
//
//	@Summary		逐 rule 执行 YAML 指纹
//	@Description	返回每条 rule 的请求 / 响应 / CEL 结果以及最终表达式判定
//	@Tags			finger
//	@Accept			json
//	@Produce		json
//	@Param			payload	body		model.RunFingerprintInput		true	"运行参数"
//	@Success		200		{object}	response.APIResponse{data=model.RunFingerprintOutput}
//	@Failure		400		{object}	response.APIResponse
//	@Failure		500		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/finger/run [post]
func (h *FingerHandler) Run(c *gin.Context) {
	var in model.RunFingerprintInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	out, err := h.Svc.Run(c.Request.Context(), &in)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, out)
}

// EvaluateCEL godoc
//
//	@Summary		CEL 表达式调试求值
//	@Description	支持注入用户自定义变量后求值，便于快速验证 CEL 写法
//	@Tags			finger
//	@Accept			json
//	@Produce		json
//	@Param			payload	body		model.EvaluateCELInput			true	"表达式 + 变量"
//	@Success		200		{object}	response.APIResponse{data=model.EvaluateCELOutput}
//	@Failure		400		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/cel/evaluate [post]
func (h *FingerHandler) EvaluateCEL(c *gin.Context) {
	var in model.EvaluateCELInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	out, err := h.Svc.EvaluateCELContext(c.Request.Context(), &in)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, out)
}

// LibraryHandler 处理指纹库 CRUD API。
type LibraryHandler struct {
	Svc *service.LibraryService
}

// DefaultDir godoc
//
//	@Summary		查询默认指纹库目录
//	@Tags			library
//	@Produce		json
//	@Success		200		{object}	response.APIResponse{data=model.DefaultLibraryDirOutput}
//	@Security		ApiToken
//	@Router			/api/v1/library/default [get]
func (h *LibraryHandler) DefaultDir(c *gin.Context) {
	response.OK(c, model.DefaultLibraryDirOutput{Path: h.Svc.DefaultDir()})
}

// List godoc
//
//	@Summary		列出指纹库下全部 yaml 文件
//	@Tags			library
//	@Produce		json
//	@Param			rootDir			query		string	false	"指纹库根目录，默认 fingerYaml/"
//	@Param			includeOutline	query		bool	false	"是否解析每个文件的 outline"
//	@Success		200				{object}	response.APIResponse{data=[]model.FingerFileMeta}
//	@Failure		400				{object}	response.APIResponse
//	@Failure		500				{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/library/list [get]
func (h *LibraryHandler) List(c *gin.Context) {
	var in model.ListLibraryInput
	if err := c.ShouldBindQuery(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	out, err := h.Svc.List(in.RootDir, in.IncludeOutline)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, out)
}

// Load godoc
//
//	@Summary		加载指定 YAML 文件内容
//	@Tags			library
//	@Produce		json
//	@Param			path	query		string	true	"绝对或相对路径"
//	@Success		200		{object}	response.APIResponse{data=model.LoadYAMLOutput}
//	@Failure		400		{object}	response.APIResponse
//	@Failure		500		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/library/load [get]
func (h *LibraryHandler) Load(c *gin.Context) {
	path := c.Query("path")
	out, err := h.Svc.Load(path)
	if err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, out)
}

// Save godoc
//
//	@Summary		保存 YAML 文件（写入前会先校验合法性）
//	@Tags			library
//	@Accept			json
//	@Produce		json
//	@Param			payload	body		model.SaveYAMLInput				true	"保存参数"
//	@Success		200		{object}	response.APIResponse
//	@Failure		400		{object}	response.APIResponse
//	@Failure		500		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/library/save [post]
func (h *LibraryHandler) Save(c *gin.Context) {
	var in model.SaveYAMLInput
	if err := c.ShouldBindJSON(&in); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.Svc.Save(&in); err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, gin.H{"path": in.Path})
}

// Delete godoc
//
//	@Summary		删除指定 YAML 文件
//	@Tags			library
//	@Produce		json
//	@Param			path	query		string	true	"要删除的文件路径"
//	@Success		200		{object}	response.APIResponse
//	@Failure		400		{object}	response.APIResponse
//	@Failure		500		{object}	response.APIResponse
//	@Security		ApiToken
//	@Router			/api/v1/library/delete [delete]
func (h *LibraryHandler) Delete(c *gin.Context) {
	path := c.Query("path")
	if err := h.Svc.Delete(path); err != nil {
		response.FromError(c, err)
		return
	}
	response.OK(c, gin.H{"path": path})
}
