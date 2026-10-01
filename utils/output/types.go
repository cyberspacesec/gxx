package output

import (
	"encoding/csv"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/wappalyzer"
	"github.com/cyberspacesec/gxx/v2/types"
	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"net"
	"os"
	"sync"
)

var (
	outputFile      *os.File
	csvWriter       *csv.Writer
	mu              sync.Mutex
	headerWritten   bool
	sockListener    net.Listener
	sockConnections = make(map[net.Conn]bool)
	sockConnMutex   sync.Mutex
)

// WriteOptions 定义写入选项结构体，用于传递写入参数
type WriteOptions struct {
	Output      string                     // 输出文件路径
	Format      string                     // 输出格式(csv/txt/json)
	Target      string                     // 目标URL
	Fingers     []*finger.Finger           // 指纹列表
	StatusCode  int32                      // 状态码
	Title       string                     // 页面标题
	ServerInfo  *types.ServerInfo          // 服务器信息
	RespHeaders string                     // 响应头
	Response    *proto.Response            // 完整响应对象(可选)
	Wappalyzer  *wappalyzer.TypeWappalyzer // 站点使用技术
	FinalResult bool                       // 最终匹配结果
	Remark      string                     // 备注(可选)
	ICP         string                     // ICP 备案号（可选）
	Certs       []*types.CertInfo          // 证书信息（可选）
}

// JSONOutput JSON格式输出结构体
type JSONOutput struct {
	URL         string                     `json:"url"`
	StatusCode  int32                      `json:"status_code"`
	Title       string                     `json:"title"`
	Server      string                     `json:"server"`
	FingerIDs   []string                   `json:"finger_ids,omitempty"`
	FingerNames []string                   `json:"finger_names,omitempty"`
	Headers     string                     `json:"headers,omitempty"`
	Wappalyzer  *wappalyzer.TypeWappalyzer `json:"wappalyzer,omitempty"`
	MatchResult bool                       `json:"match_result"`
	Remark      string                     `json:"remark,omitempty"`
	ICP         string                     `json:"icp,omitempty"`
	Certs       []*types.CertInfo          `json:"certs,omitempty"`
}

// TargetResult 存储每个目标的扫描结果
type TargetResult struct {
	URL        string                     // 目标地址
	StatusCode int32                      // 状态码
	Title      string                     // 站点标题
	ServerInfo *types.ServerInfo          // server信息
	Fingers    []*finger.Finger           // 匹配的指纹列表
	Matches    []*FingerMatch             // 匹配详细信息
	Wappalyzer *wappalyzer.TypeWappalyzer // 站点信息数据
	ICP        string                     // ICP 备案号
	Certs      []*types.CertInfo          // 证书信息
}

// FingerMatch 存储每个匹配的指纹信息
type FingerMatch struct {
	Finger   *finger.Finger  // 指纹信息
	Result   bool            // 识别结果
	Request  *proto.Request  // 请求数据
	Response *proto.Response // 响应数据
}
