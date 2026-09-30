/*
Package runner 提供指纹识别的运行时核心。
*/
package runner

import (
	"golang.org/x/sync/singleflight"
	"time"

	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/wappalyzer"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/logger"
	"github.com/cyberspacesec/gxx/utils/proto"
	"net/http"
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
	pageURL    string
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
}

// FingerMatch 单条指纹匹配结果。
type FingerMatch struct {
	Finger   *finger.Finger
	Result   bool
	Request  *proto.Request
	Response *proto.Response
}

// BaseInfo 仅含规则匹配所需的少量基础字段，放入 varMap 给 CEL 使用。
type BaseInfo struct {
	Title      string
	Server     *types.ServerInfo
	StatusCode int32
	response   *proto.Response
	requests   singleflight.Group
	cache      *CacheManager
}

// ScanConfig 扫描配置参数。
type ScanConfig struct {
	Reverse           types.ReverseConfig
	Proxy             string
	Timeout           time.Duration
	URLWorkerCount    int
	FingerWorkerCount int
	OutputFormat      string
	OutputFile        string
	SockOutputFile    string

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

	DisableKeepAlives  bool
	InsecureSkipVerify bool
	CustomHeaders      map[string]string
	Debug              bool
}

// RulePoolStats 规则池任务统计。
type RulePoolStats struct {
	TotalTasks     int64
	CompletedTasks int64
	FailedTasks    int64
}
