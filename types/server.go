/*
  - Package types
    @Author: zhizhuo
    @IDE：GoLand
    @File: server.go
    @Date: 2025/4/4 上午10:25*
*/
package types

// ServerInfo 定义服务器信息的结构体
type ServerInfo struct {
	OriginalServer string `json:"original_server"` // 原始服务器信息
	ServerType     string `json:"server_type"`     // 服务器类型
	Version        string `json:"version"`         // 版本号
}

// NewServerInfo 创建新的ServerInfo对象
func NewServerInfo(originalServer, serverType, version string) *ServerInfo {
	return &ServerInfo{
		OriginalServer: originalServer,
		ServerType:     serverType,
		Version:        version,
	}
}

// EmptyServerInfo 返回空的ServerInfo对象
func EmptyServerInfo() *ServerInfo {
	return &ServerInfo{
		OriginalServer: "",
		ServerType:     "",
		Version:        "",
	}
}
