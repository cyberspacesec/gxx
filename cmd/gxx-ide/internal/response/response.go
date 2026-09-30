// Package response 定义 GXX IDE HTTP API 的统一响应格式。
//
// 所有 handler 一律通过本包提供的 OK / BadRequest / ServerError 等
// 帮手函数返回 JSON，确保 {code, message, data} 字段名与状态码语义一致。
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// API 标准响应结构。
type APIResponse struct {
	Code    int    `json:"code" example:"200"`
	Message string `json:"message" example:"success"`
	Data    any    `json:"data,omitempty" swaggertype:"object"`
}

const (
	// MsgSuccess 默认成功提示。
	MsgSuccess = "success"
	// MsgBadRequest 默认 400 提示。
	MsgBadRequest = "请求参数错误"
	// MsgServerError 默认 500 提示。
	MsgServerError = "服务端错误"
)

// OK 返回 200 + 业务数据。
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, APIResponse{
		Code:    http.StatusOK,
		Message: MsgSuccess,
		Data:    data,
	})
}

// BadRequest 返回 400 + 错误说明，用于参数校验失败、JSON 解析失败等。
func BadRequest(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusBadRequest, APIResponse{
		Code:    http.StatusBadRequest,
		Message: message,
	})
}

// ServerError 返回 500 + 错误说明，用于服务端内部异常。
func ServerError(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, APIResponse{
		Code:    http.StatusInternalServerError,
		Message: message,
	})
}

// FromError 根据 error 自动选择 400 / 500。
//
//   - nil error 不会调用任何 abort；
//   - 当 err 实现 BadRequestError 接口时返回 400；
//   - 其他 error 一律 500。
func FromError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	if _, ok := err.(BadRequestError); ok {
		BadRequest(c, err.Error())
		return
	}
	ServerError(c, err.Error())
}

// BadRequestError 是约定的 400 类型错误接口。
// service 层可让某个 error 实现 BadRequest() 表明该错误应回 400 而非 500。
type BadRequestError interface {
	error
	BadRequest() bool
}

// NewBadRequest 创建一个标识为 400 的错误。
func NewBadRequest(msg string) error {
	return &badRequestErr{msg: msg}
}

type badRequestErr struct {
	msg string
}

func (b *badRequestErr) Error() string    { return b.msg }
func (b *badRequestErr) BadRequest() bool { return true }
