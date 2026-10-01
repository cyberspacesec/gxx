package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/types"
	"net/http"
)

func TestCleanServerString(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantCleaned string
	}{
		{
			name:        "无需清理",
			server:      "nginx/1.18.0",
			wantCleaned: "nginx/1.18.0",
		},
		{
			name:        "清理括号",
			server:      "Apache/2.4.41 (Ubuntu)",
			wantCleaned: "Apache/2.4.41",
		},
		{
			name:        "清理修饰词",
			server:      "powered by Apache",
			wantCleaned: "Apache",
		},
		{
			name:        "清理多个修饰词",
			server:      "powered by Apache running on CentOS",
			wantCleaned: "Apache CentOS",
		},
		{
			name:        "复杂清理",
			server:      "   Apache/2.4.41 (Ubuntu)  (SSL) powered by PHP/7.4  ",
			wantCleaned: "Apache/2.4.41    PHP/7.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := finger.CleanServerString(tt.server); got != tt.wantCleaned {
				t.Errorf("cleanServerString() = %v, 期望 %v", got, tt.wantCleaned)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "无版本号",
			server:      "Apache",
			wantVersion: "",
		},
		{
			name:        "标准版本号",
			server:      "nginx/1.18.0",
			wantVersion: "1.18.0",
		},
		{
			name:        "双段版本号",
			server:      "Apache/2.4",
			wantVersion: "2.4",
		},
		{
			name:        "版本号在中间",
			server:      "Microsoft-IIS/10.0 ASP.NET",
			wantVersion: "10.0",
		},
		{
			name:        "多个版本号时取第一个",
			server:      "Apache/2.4.41 PHP/7.4.3",
			wantVersion: "2.4.41",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println(tt.name, tt.wantVersion, tt.server)
			if got := finger.ExtractVersion(tt.server); got != tt.wantVersion {
				t.Errorf("extractVersion() = %v, 期望 %v", got, tt.wantVersion)
			}
		})
	}
}

func TestFormatServerResult(t *testing.T) {
	tests := []struct {
		name           string
		originalServer string
		cleanedServer  string
		version        string
		wantContains   []string
	}{
		{
			name:           "完整信息",
			originalServer: "Apache/2.4.41 (Ubuntu)",
			cleanedServer:  "Apache/2.4.41",
			version:        "2.4.41",
			wantContains: []string{
				"原始服务器信息: Apache/2.4.41 (Ubuntu)",
				"服务器类型: Apache/2.4.41",
				"版本号: 2.4.41",
			},
		},
		{
			name:           "无版本信息",
			originalServer: "Apache (Ubuntu)",
			cleanedServer:  "Apache",
			version:        "",
			wantContains: []string{
				"原始服务器信息: Apache (Ubuntu)",
				"服务器类型: Apache",
				"版本号: 未知",
			},
		},
		{
			name:           "空服务器类型",
			originalServer: "Unknown Server",
			cleanedServer:  "",
			version:        "",
			wantContains: []string{
				"原始服务器信息: Unknown Server",
				"服务器类型: 未知",
				"版本号: 未知",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := finger.FormatServerResult(tt.originalServer, tt.cleanedServer, tt.version)

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("FormatServerResult() 结果中没有找到预期内容: %s", want)
				}
			}
		})
	}
}

// TestGetServerInfoFromResponse 测试从HTTP响应获取JSON格式的服务器信息
func TestGetServerInfoFromResponse(t *testing.T) {
	tests := []struct {
		name        string
		serverValue string
		wantInfo    *types.ServerInfo
	}{
		{
			name:        "正常响应",
			serverValue: "nginx/1.18.0",
			wantInfo: &types.ServerInfo{
				OriginalServer: "nginx/1.18.0",
				ServerType:     "nginx/1.18.0",
				Version:        "1.18.0",
			},
		},
		{
			name:        "带括号的服务器",
			serverValue: "Apache/2.4.41 (Ubuntu)",
			wantInfo: &types.ServerInfo{
				OriginalServer: "Apache/2.4.41 (Ubuntu)",
				ServerType:     "Apache/2.4.41 (Ubuntu)",
				Version:        "2.4.41",
			},
		},
		{
			name:        "空服务器信息",
			serverValue: "",
			wantInfo:    types.EmptyServerInfo(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟的HTTP响应
			resp := &http.Response{
				Header: make(http.Header),
			}

			if tt.serverValue != "" {
				resp.Header.Set("Server", tt.serverValue)
			}

			// 获取服务器信息结构体
			gotInfo := finger.GetServerInfoFromResponse(resp)

			// 验证内容符合预期
			if gotInfo.OriginalServer != tt.wantInfo.OriginalServer {
				t.Errorf("OriginalServer = %v, 期望 %v", gotInfo.OriginalServer, tt.wantInfo.OriginalServer)
			}
			if gotInfo.ServerType != tt.wantInfo.ServerType {
				t.Errorf("ServerType = %v, 期望 %v", gotInfo.ServerType, tt.wantInfo.ServerType)
			}
			if gotInfo.Version != tt.wantInfo.Version {
				t.Errorf("Version = %v, 期望 %v", gotInfo.Version, tt.wantInfo.Version)
			}
		})
	}
}

// TestGetServerInfoFromTCP 测试从TCP/UDP连接获取JSON格式的服务器信息
func TestGetServerInfoFromTCP(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		hostType string
		wantInfo *types.ServerInfo
	}{
		{
			name:     "TCP服务器",
			address:  "example.com:80",
			hostType: "TCP",
			wantInfo: &types.ServerInfo{
				OriginalServer: "TCP example.com:80",
				ServerType:     "TCP",
				Version:        "未知",
			},
		},
		{
			name:     "UDP服务器",
			address:  "example.com:53",
			hostType: "UDP",
			wantInfo: &types.ServerInfo{
				OriginalServer: "UDP example.com:53",
				ServerType:     "UDP",
				Version:        "未知",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 获取服务器信息结构体
			gotInfo := finger.GetServerInfoFromTCP(tt.address, tt.hostType)

			// 验证内容符合预期
			if gotInfo.OriginalServer != tt.wantInfo.OriginalServer {
				t.Errorf("OriginalServer = %v, 期望 %v", gotInfo.OriginalServer, tt.wantInfo.OriginalServer)
			}
			if gotInfo.ServerType != tt.wantInfo.ServerType {
				t.Errorf("ServerType = %v, 期望 %v", gotInfo.ServerType, tt.wantInfo.ServerType)
			}
			if gotInfo.Version != tt.wantInfo.Version {
				t.Errorf("Version = %v, 期望 %v", gotInfo.Version, tt.wantInfo.Version)
			}
		})
	}
}

// TestServerInfoSerialization 测试ServerInfo结构体的序列化和反序列化
func TestServerInfoSerialization(t *testing.T) {
	tests := []struct {
		name       string
		serverInfo *types.ServerInfo
	}{
		{
			name: "完整信息",
			serverInfo: &types.ServerInfo{
				OriginalServer: "Apache/2.4.41 (Ubuntu)",
				ServerType:     "Apache",
				Version:        "2.4.41",
			},
		},
		{
			name: "部分缺失信息",
			serverInfo: &types.ServerInfo{
				OriginalServer: "nginx",
				ServerType:     "nginx",
				Version:        "",
			},
		},
		{
			name:       "空信息",
			serverInfo: types.EmptyServerInfo(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 序列化为JSON
			jsonData, err := json.Marshal(tt.serverInfo)
			if err != nil {
				t.Errorf("json.Marshal() 失败: %v", err)
				return
			}

			// 反序列化回ServerInfo对象
			var gotInfo types.ServerInfo
			err = json.Unmarshal(jsonData, &gotInfo)
			if err != nil {
				t.Errorf("json.Unmarshal() 失败: %v", err)
				return
			}

			// 验证反序列化后的对象与原对象相同
			if gotInfo.OriginalServer != tt.serverInfo.OriginalServer {
				t.Errorf("OriginalServer = %v, 期望 %v", gotInfo.OriginalServer, tt.serverInfo.OriginalServer)
			}
			if gotInfo.ServerType != tt.serverInfo.ServerType {
				t.Errorf("ServerType = %v, 期望 %v", gotInfo.ServerType, tt.serverInfo.ServerType)
			}
			if gotInfo.Version != tt.serverInfo.Version {
				t.Errorf("Version = %v, 期望 %v", gotInfo.Version, tt.serverInfo.Version)
			}
		})
	}
}

// DisplayServerInfo 格式化显示服务器信息，以简洁方式显示服务器名称和版本
func DisplayServerInfo(originalServer, cleanedServer, version string) string {
	if cleanedServer == "" {
		return "未检测到服务器信息"
	}

	if version == "" {
		return fmt.Sprintf("服务器信息为%s 版本未知", cleanedServer)
	}
	return fmt.Sprintf("服务器信息为%s 版本%s", cleanedServer, version)
}

// TestDisplayServerInfo 测试服务器信息的简洁格式化显示
func TestDisplayServerInfo(t *testing.T) {
	tests := []struct {
		name           string
		originalServer string
		cleanedServer  string
		version        string
		want           string
	}{
		{
			name:           "完整信息",
			originalServer: "Apache/2.4.41 (Ubuntu)",
			cleanedServer:  "Apache",
			version:        "2.4.41",
			want:           "服务器信息为Apache 版本2.4.41",
		},
		{
			name:           "仅服务器无版本",
			originalServer: "Apache (Ubuntu)",
			cleanedServer:  "Apache",
			version:        "",
			want:           "服务器信息为Apache 版本未知",
		},
		{
			name:           "未知服务器",
			originalServer: "Unknown Server",
			cleanedServer:  "",
			version:        "",
			want:           "未检测到服务器信息",
		},
		{
			name:           "Nginx服务器",
			originalServer: "nginx/1.18.0",
			cleanedServer:  "nginx",
			version:        "1.18.0",
			want:           "服务器信息为nginx 版本1.18.0",
		},
		{
			name:           "IIS服务器",
			originalServer: "Microsoft-IIS/10.0 (Windows Server 2019)",
			cleanedServer:  "Microsoft-IIS",
			version:        "10.0",
			want:           "服务器信息为Microsoft-IIS 版本10.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DisplayServerInfo(tt.originalServer, tt.cleanedServer, tt.version)
			fmt.Println(got)
			if got != tt.want {
				t.Errorf("DisplayServerInfo() = %v, 期望 %v", got, tt.want)
			}
		})
	}
}

// TestServerInfoIntegration 集成测试，测试server信息与variableMap的交互
func TestServerInfoIntegration(t *testing.T) {
	// 模拟一个HTTP响应
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "nginx/1.18.0")

	// 创建variableMap
	variableMap := make(map[string]any)

	// 获取服务器信息并存入variableMap
	serverInfo := finger.GetServerInfoFromResponse(resp)
	jsonData, _ := json.Marshal(serverInfo)
	variableMap["server"] = string(jsonData)

	// 验证variableMap中的server信息是否正确
	serverStr, ok := variableMap["server"].(string)
	if !ok {
		t.Errorf("variableMap[\"server\"] 不是字符串类型")
		return
	}

	// 解析JSON
	var parsedServerInfo types.ServerInfo
	err := json.Unmarshal([]byte(serverStr), &parsedServerInfo)
	if err != nil {
		t.Errorf("解析server JSON失败: %v", err)
		return
	}

	// 验证内容
	if parsedServerInfo.OriginalServer != "nginx/1.18.0" {
		t.Errorf("OriginalServer = %v, 期望 nginx/1.18.0", parsedServerInfo.OriginalServer)
	}
	if parsedServerInfo.ServerType != "nginx/1.18.0" {
		t.Errorf("ServerType = %v, 期望 nginx/1.18.0", parsedServerInfo.ServerType)
	}
	if parsedServerInfo.Version != "1.18.0" {
		t.Errorf("Version = %v, 期望 1.18.0", parsedServerInfo.Version)
	}

	// 测试TCP服务器信息
	tcpServerInfo := finger.GetServerInfoFromTCP("example.com:80", "TCP")
	tcpJsonData, _ := json.Marshal(tcpServerInfo)
	variableMap["server"] = string(tcpJsonData)

	// 验证variableMap中的TCP server信息是否正确
	tcpServerStr, ok := variableMap["server"].(string)
	if !ok {
		t.Errorf("variableMap[\"server\"] 不是字符串类型")
		return
	}

	// 解析JSON
	var parsedTcpServerInfo types.ServerInfo
	err = json.Unmarshal([]byte(tcpServerStr), &parsedTcpServerInfo)
	if err != nil {
		t.Errorf("解析TCP server JSON失败: %v", err)
		return
	}

	// 验证内容
	expectedOriginalServer := "TCP example.com:80"
	if parsedTcpServerInfo.OriginalServer != expectedOriginalServer {
		t.Errorf("OriginalServer = %v, 期望 %v", parsedTcpServerInfo.OriginalServer, expectedOriginalServer)
	}
	if parsedTcpServerInfo.ServerType != "TCP" {
		t.Errorf("ServerType = %v, 期望 TCP", parsedTcpServerInfo.ServerType)
	}
	if parsedTcpServerInfo.Version != "未知" {
		t.Errorf("Version = %v, 期望 未知", parsedTcpServerInfo.Version)
	}
}

// TestParseServerJSON 测试解析server JSON的场景
func TestParseServerJSON(t *testing.T) {
	// 创建一些测试用的JSON数据
	testCases := []struct {
		name           string
		jsonData       string
		expectedServer types.ServerInfo
		expectError    bool
	}{
		{
			name:     "有效的完整JSON",
			jsonData: `{"original_server":"nginx/1.18.0","server_type":"nginx","version":"1.18.0"}`,
			expectedServer: types.ServerInfo{
				OriginalServer: "nginx/1.18.0",
				ServerType:     "nginx",
				Version:        "1.18.0",
			},
			expectError: false,
		},
		{
			name:     "有效的部分JSON",
			jsonData: `{"original_server":"Apache","server_type":"Apache","version":""}`,
			expectedServer: types.ServerInfo{
				OriginalServer: "Apache",
				ServerType:     "Apache",
				Version:        "",
			},
			expectError: false,
		},
		{
			name:     "空JSON对象",
			jsonData: `{"original_server":"","server_type":"","version":""}`,
			expectedServer: types.ServerInfo{
				OriginalServer: "",
				ServerType:     "",
				Version:        "",
			},
			expectError: false,
		},
		{
			name:        "无效的JSON",
			jsonData:    `{"original_server":"nginx/1.18.0","server_type":"nginx"`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var serverInfo types.ServerInfo
			err := json.Unmarshal([]byte(tc.jsonData), &serverInfo)

			if tc.expectError {
				if err == nil {
					t.Errorf("期望解析错误，但没有发生错误")
				}
				return
			}

			if err != nil {
				t.Errorf("解析JSON出错: %v", err)
				return
			}

			if serverInfo.OriginalServer != tc.expectedServer.OriginalServer {
				t.Errorf("OriginalServer = %v, 期望 %v", serverInfo.OriginalServer, tc.expectedServer.OriginalServer)
			}
			if serverInfo.ServerType != tc.expectedServer.ServerType {
				t.Errorf("ServerType = %v, 期望 %v", serverInfo.ServerType, tc.expectedServer.ServerType)
			}
			if serverInfo.Version != tc.expectedServer.Version {
				t.Errorf("Version = %v, 期望 %v", serverInfo.Version, tc.expectedServer.Version)
			}
		})
	}
}

func TestGetServerInfo(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 Server 探测测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	server := finger.GetServerInfoFromResponse(resp)
	if server == nil {
		t.Fatal("server info is nil")
	}
	fmt.Println(server.ServerType)
}
