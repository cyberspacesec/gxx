/*
Package runner 提供指纹识别的运行时核心。
*/
package runner

import (
	"golang.org/x/sync/singleflight"
	"time"

	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/pkg/wappalyzer"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"net/http"
	"net/url"
)

// 全局并发常量。
const (
	DefaultURLWorkers  = 5
	DefaultRuleWorkers = 200
	MaxRuleWorkers     = 5000
	MinRuleWorkers     = 200
)

// BaseInfoResponse 包含目标基础信息和 HTTP 响应。
type BaseInfoResponse struct {
	Url        string
	Title      string
	Server     *types.ServerInfo
	StatusCode int32
	Response   *http.Response
	Wappalyzer *wappalyzer.TypeWappalyzer
	BodyBytes  []byte
	ICP        string
	Certs      []*types.CertInfo
	// FinalURL 是跳转链最后一页的地址；RedirectTo 是页面里识别出的、指向其他资产而未跟随的跳转目标。
	FinalURL   string
	RedirectTo string
	Redirects  []Redirect
	// HeaderOrder 是最后一页的响应头名称，按服务器发送的顺序；TLS 是最后一页所在连接的握手摘要。
	HeaderOrder []string
	TLS         *network.TLSInfo
	// Icon 是最后一页图标的证据，开启 IconEvidence 时记录。
	Icon *finger.IconEvidence
	// Resources 是最后一页所在资产的附属资源，开启 Resources 时读取。
	Resources []Resource
	pages     []*scanPage
	origin    *url.URL // 入口所在的资产
}

// Redirect 入口跳转链上的一跳。Followed 为 false 表示页面里识别出的跳转指向其他资产，没有访问。
type Redirect struct {
	Type     string // http / refresh / javascript
	Status   int32  // 发出跳转的响应的状态码
	From     string
	To       string
	Followed bool
}

// scanPage 入口跳转链上的一页响应。链上每一页都参与根路径规则的匹配。
type scanPage struct {
	url      string
	status   int32
	header   http.Header
	body     []byte
	request  *proto.Request
	response *proto.Response
	source   *http.Response // 实际读取的响应，正文已关闭，只用于连接信息
	// truncated 表示正文超过读取上限被截断。
	truncated bool
}

// TargetResult 单个目标的扫描结果。
type TargetResult struct {
	URL          string
	StatusCode   int32
	Title        string
	Server       *types.ServerInfo
	Matches      []*FingerMatch
	Wappalyzer   *wappalyzer.TypeWappalyzer
	LastRequest  *proto.Request
	LastResponse *proto.Response
	ICP          string
	Certs        []*types.CertInfo
	FinalURL     string
	RedirectTo   string
	Redirects    []Redirect
	HeaderOrder  []string
	TLS          *network.TLSInfo
	Icon         *finger.IconEvidence
	Resources    []Resource
}

// FingerMatch 单条指纹匹配结果。
type FingerMatch struct {
	Finger           *finger.Finger
	Result           bool
	Request          *proto.Request
	Response         *proto.Response
	MatchedRules     []SubRuleMatch
	ProductVersion   string
	ProductVersions  []string
	VersionConflict  bool
	DetailsTruncated bool
}

// SubRuleMatch 只记录成功匹配的子规则，不保留原始响应。
type SubRuleMatch struct {
	Key               string
	Expression        string
	Method            string
	Path              string
	URL               string
	StatusCode        int32
	Evidence          []cel.Evidence
	EvidenceTruncated bool
	Outputs           map[string]string
}

// BaseInfo 仅含规则匹配所需的少量基础字段，放入 varMap 给 CEL 使用。
type BaseInfo struct {
	Title      string
	Server     *types.ServerInfo
	StatusCode int32
	request    *proto.Request
	response   *proto.Response
	// rootTarget/rootURL 缓存本次扫描目标拼接根路径 "/" 的结果：内置规则几乎都请求
	// 根路径，避免每条规则重复拼接字符串。
	rootTarget string
	rootURL    string
	// earlier 是跳转链上最终页之前的各页（入口 30x、跳转壳），按从后到前排列。
	earlier  []*scanPage
	requests singleflight.Group
	cache    *CacheManager
	scan     *scanState
}

// ScanConfig 扫描配置参数。
type ScanConfig struct {
	CaptureEvidence   bool
	Reverse           types.ReverseConfig
	Proxy             string
	Timeout           time.Duration
	URLWorkerCount    int
	FingerWorkerCount int

	Logger           logger.Sink
	CacheMaxBytes    uint64
	CacheMaxSize     int
	CacheTTL         time.Duration
	MemHighBytes     uint64
	MemCriticalBytes uint64
	EnableMonitor    bool
	EnableProactive  bool

	RateLimitQPS   float64
	RateLimitBurst int
	// RateLimitPerPort 为 true 时每主机限速按“主机:端口”区分，默认按主机合并。
	RateLimitPerPort bool
	// GlobalRateLimit 是实例全部请求的总速率上限（次/秒），0 表示不限制。
	GlobalRateLimit      float64
	GlobalRateLimitBurst int

	DisableKeepAlives  bool
	InsecureSkipVerify bool
	CustomHeaders      map[string]string
	Debug              bool

	// Policy 是引擎级网络策略，约束全部出站连接。
	Policy network.Policy
	// BodyLimit 是响应正文的读取上限（字节），0 表示 network.MaxDefaultBody。
	BodyLimit int64
	// ResponseCacheBudget 是每次扫描的响应归一化缓存预算（字节），0 表示默认 8 MiB。
	ResponseCacheBudget int64
	// IconEvidence 为 true 时记录最终页面图标的证据，原始字节最多保留 IconEvidenceData。
	IconEvidence     bool
	IconEvidenceData int
	// JARM 为 true 时为 HTTPS 目标计算 JARM 指纹（另发 10 个 TLS 探测）。
	JARM bool
	// Resources 选择要读取的附属资源，默认全关。
	Resources ResourceOptions
	// RulePolicy 在加载与重新加载规则时检查，违反即加载失败。
	RulePolicy finger.RulePolicy
}

// ScanOptions 是单次扫描的附加配置，零值与普通扫描相同。
type ScanOptions struct {
	// Policy 逐字段覆盖引擎级网络策略，只作用于本次扫描。
	Policy network.Policy
	// Report 非 nil 时，扫描结束（含失败与取消）后写入求值报告。
	Report *EvaluationReport
	// Observer 非 nil 时，每次交换完成后串行回调。
	Observer       func(network.Exchange)
	ExchangeLimits network.ExchangeLimits
}

// RulePoolStats 规则池任务统计。
type RulePoolStats struct {
	TotalTasks     int64
	CompletedTasks int64
	FailedTasks    int64
}
