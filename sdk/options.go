/*
Package sdk Functional Options 定义。

Engine 的所有配置通过 Option 注入，NewEngine 在构造期一次性 apply。
*/
package sdk

import (
	"fmt"
	"github.com/cyberspacesec/gxx/types"
	"log/slog"
	"time"
)

// engineConfig 引擎内部配置，外部只能通过 Option 修改。
type engineConfig struct {
	matchDetails      bool
	products          []ProductDefinition
	assessments       []RuleAssessment
	ruleSourceVersion string
	reverse           types.ReverseConfig
	// 指纹相关
	fingerOptions FingerOptions

	// 网络层
	proxy              string
	timeout            time.Duration
	insecureSkipVerify bool
	disableKeepAlives  bool
	customHeaders      map[string]string

	// 并发控制
	urlConcurrency  int
	ruleConcurrency int

	// 缓存
	cacheMaxBytes int64
	cacheMaxSize  int
	cacheTTL      time.Duration

	// 监控
	enableMonitor    bool
	enableProactive  bool
	memHighBytes     uint64
	memCriticalBytes uint64

	// 限流（per-host rate limiter）
	enableRateLimit bool
	rateLimitQPS    float64
	rateLimitBurst  int

	// 调试
	debug  bool
	logger *slog.Logger

	// 输出
	outputFile     string
	outputFormat   OutputFormat
	sockOutputFile string
	customWriters  []Writer
}

// WithRuleAssessments 提供带规则摘要的样本测试记录或校准置信度。
// 测试记录只作用于完全相同的规则内容。
func WithRuleAssessments(assessments []RuleAssessment) Option {
	snapshot := cloneAssessments(assessments)
	return func(c *engineConfig) error {
		if err := validateAssessments(snapshot); err != nil {
			return err
		}
		c.assessments = cloneAssessments(snapshot)
		return nil
	}
}

// defaultEngineConfig 返回引擎的默认配置。
func defaultEngineConfig() engineConfig {
	return engineConfig{
		matchDetails:       true,
		timeout:            10 * time.Second,
		insecureSkipVerify: true,
		disableKeepAlives:  false,
		urlConcurrency:     5,
		ruleConcurrency:    200,
		cacheMaxSize:       2048,
		cacheTTL:           10 * time.Minute,
		enableMonitor:      false,
		enableProactive:    false,
		memHighBytes:       2 * 1024 * 1024 * 1024,
		memCriticalBytes:   4 * 1024 * 1024 * 1024,
		enableRateLimit:    false,
		rateLimitQPS:       50,
		rateLimitBurst:     100,
	}
}

// WithMatchDetails 控制命中子规则与证据回传；产品版本和元数据始终保留。
func WithMatchDetails(enabled bool) Option {
	return func(c *engineConfig) error { c.matchDetails = enabled; return nil }
}

// WithRuleSourceVersion 声明外部规则包的版本，不影响 SDK 的版本。
func WithRuleSourceVersion(version string) Option {
	return func(c *engineConfig) error { c.ruleSourceVersion = version; return nil }
}

// WithProductCatalog 将系统产品目录映射到明确的规则 ID，不从规则作者推测厂商。
// 参数及每个 Engine 的配置均使用独立副本。
func WithProductCatalog(products []ProductDefinition) Option {
	snapshot := cloneProductDefinitions(products)
	return func(c *engineConfig) error {
		if err := validateProductDefinitions(snapshot); err != nil {
			return err
		}
		c.products = cloneProductDefinitions(snapshot)
		return nil
	}
}

// Option 配置 Engine 的函数式选项。
//
// 用法：
//
//	engine, err := sdk.NewEngine(ctx,
//	    sdk.WithTimeout(15 * time.Second),
//	    sdk.WithProxy("http://127.0.0.1:8080"),
//	    sdk.WithRuleConcurrency(500),
//	)
type Option func(*engineConfig) error

// WithFingerOptions 指定指纹规则文件 / 目录路径。
// 若为空则使用嵌入式指纹库。
func WithFingerOptions(opts FingerOptions) Option {
	return func(c *engineConfig) error {
		c.fingerOptions = opts
		return nil
	}
}

// ReverseConfig 描述当前 Engine 的 Ceye 与 JNDI 反连服务。
type ReverseConfig = types.ReverseConfig

// WithReverseConfig 按值设置反连服务，多个 Engine 的查询配置互不影响。
func WithReverseConfig(config ReverseConfig) Option {
	return func(c *engineConfig) error {
		c.reverse = config
		return nil
	}
}

// WithProxy 设置 HTTP/HTTPS/SOCKS5 代理地址，空字符串表示不使用代理。
func WithProxy(proxy string) Option {
	return func(c *engineConfig) error {
		c.proxy = proxy
		return nil
	}
}

// WithTimeout 设置请求超时时间，必须 > 0。
func WithTimeout(d time.Duration) Option {
	return func(c *engineConfig) error {
		if d <= 0 {
			return fmt.Errorf("%w: timeout must be > 0, got %v", ErrInvalidOption, d)
		}
		c.timeout = d
		return nil
	}
}

// WithTimeoutSeconds 设置请求超时时间，单位为秒。
func WithTimeoutSeconds(seconds int) Option {
	return func(c *engineConfig) error {
		if seconds <= 0 {
			return fmt.Errorf("%w: timeout seconds must be > 0, got %d", ErrInvalidOption, seconds)
		}
		c.timeout = time.Duration(seconds) * time.Second
		return nil
	}
}

// WithInsecureSkipVerify 是否跳过 TLS 证书验证（默认 true，扫描场景普遍需要）。
func WithInsecureSkipVerify(skip bool) Option {
	return func(c *engineConfig) error {
		c.insecureSkipVerify = skip
		return nil
	}
}

// WithDisableKeepAlives 是否禁用 HTTP Keep-Alive。
// 默认 false（启用 Keep-Alive），仅在遇 "Unsolicited response" 等兼容性问题时显式关闭。
func WithDisableKeepAlives(disable bool) Option {
	return func(c *engineConfig) error {
		c.disableKeepAlives = disable
		return nil
	}
}

// WithCustomHeaders 设置当前实例的自定义请求头。
func WithCustomHeaders(headers map[string]string) Option {
	return func(c *engineConfig) error {
		if c.customHeaders == nil {
			c.customHeaders = make(map[string]string, len(headers))
		}
		for k, v := range headers {
			c.customHeaders[k] = v
		}
		return nil
	}
}

// WithURLConcurrency 设置 URL 处理并发数（默认 5）。
func WithURLConcurrency(n int) Option {
	return func(c *engineConfig) error {
		if n <= 0 {
			return fmt.Errorf("%w: url concurrency must be > 0, got %d", ErrInvalidOption, n)
		}
		c.urlConcurrency = n
		return nil
	}
}

// WithRuleConcurrency 设置规则识别并发上限（默认 200）。
// 纯匹配与慢网络请求的最佳并发不同，应按实际负载测量。
func WithRuleConcurrency(n int) Option {
	return func(c *engineConfig) error {
		if n <= 0 {
			return fmt.Errorf("%w: rule concurrency must be > 0, got %d", ErrInvalidOption, n)
		}
		c.ruleConcurrency = n
		return nil
	}
}

// WithCacheSize 设置请求/响应缓存最大条目数（默认 2048）。
func WithCacheSize(size int) Option {
	return func(c *engineConfig) error {
		if size <= 0 {
			return fmt.Errorf("%w: cache size must be > 0, got %d", ErrInvalidOption, size)
		}
		c.cacheMaxSize = size
		return nil
	}
}

// WithCacheTTL 设置缓存条目的 TTL（默认 10 分钟）。
func WithCacheTTL(ttl time.Duration) Option {
	return func(c *engineConfig) error {
		if ttl <= 0 {
			return fmt.Errorf("%w: cache TTL must be > 0, got %v", ErrInvalidOption, ttl)
		}
		c.cacheTTL = ttl
		return nil
	}
}

// WithMemoryMonitor 启用内存监控（默认关闭）。
func WithMemoryMonitor(enable bool) Option {
	return func(c *engineConfig) error {
		c.enableMonitor = enable
		return nil
	}
}

// WithMemoryThresholds 设置内存高位 / 临界阈值（字节）。
func WithMemoryThresholds(highBytes, criticalBytes uint64) Option {
	return func(c *engineConfig) error {
		if highBytes == 0 || criticalBytes == 0 || criticalBytes < highBytes {
			return fmt.Errorf("%w: invalid memory thresholds high=%d critical=%d", ErrInvalidOption, highBytes, criticalBytes)
		}
		c.memHighBytes = highBytes
		c.memCriticalBytes = criticalBytes
		return nil
	}
}

// WithProactiveGC 启用主动 GC（默认关闭，避免 STW 放大尾延迟）。
func WithProactiveGC(enable bool) Option {
	return func(c *engineConfig) error {
		c.enableProactive = enable
		return nil
	}
}

// WithRateLimit 启用 per-host 速率限制。
//
// 参数：
//   - qps: 每个 host 每秒允许的请求数（令牌产生速率）
//   - burst: 令牌桶容量（瞬时突发上限）
//
// 用于防止高并发扫描时单目标被限流误判，每个 host 独立持有令牌桶。
func WithRateLimit(qps float64, burst int) Option {
	return func(c *engineConfig) error {
		if qps <= 0 || burst <= 0 {
			return fmt.Errorf("%w: rate limit qps/burst must be > 0", ErrInvalidOption)
		}
		c.enableRateLimit = true
		c.rateLimitQPS = qps
		c.rateLimitBurst = burst
		return nil
	}
}

// WithDebug 启用调试日志（仅影响日志详细程度，不改变扫描行为）。
// 未调用 logger.InitLogger 时同样生效。
func WithDebug(enable bool) Option {
	return func(c *engineConfig) error {
		c.debug = enable
		return nil
	}
}

// WithOutputFile 把每个完成扫描的目标结果写入本地文件。
//
//   - path:   目标文件路径，父目录会被自动创建，空字符串表示不启用；
//   - format: txt / csv / json，未知值回退到 txt。
//
// 内部使用实例化的 FileWriter（自带异步队列），多 Engine 互不影响。
func WithOutputFile(path string, format OutputFormat) Option {
	return func(c *engineConfig) error {
		c.outputFile = path
		c.outputFormat = format
		return nil
	}
}

// WithSockOutputFile 通过 Unix domain socket 推送 JSON Lines 结果。
//
// path 为空时不启用；socket 文件已存在时会被删除后重新创建。
func WithSockOutputFile(path string) Option {
	return func(c *engineConfig) error {
		c.sockOutputFile = path
		return nil
	}
}

// WithWriter 注入自定义 Writer（可调用多次累加），
// 与 WithOutputFile / WithSockOutputFile 同时使用时会被合并到 MultiWriter。
func WithWriter(w Writer) Option {
	return func(c *engineConfig) error {
		if w == nil {
			return fmt.Errorf("%w: writer must not be nil", ErrInvalidOption)
		}
		c.customWriters = append(c.customWriters, w)
		return nil
	}
}

// WithCacheBytes 设置请求缓存的估算字节预算（默认 64 MiB），与条目上限同时生效。
func WithCacheBytes(size int64) Option {
	return func(c *engineConfig) error {
		if size <= 0 {
			return fmt.Errorf("%w: cache byte budget must be > 0", ErrInvalidOption)
		}
		c.cacheMaxBytes = size
		return nil
	}
}

// WithLogger 注入实例独立的标准库日志器。未配置时 SDK 不输出日志。
func WithLogger(log *slog.Logger) Option {
	return func(c *engineConfig) error { c.logger = log; return nil }
}
