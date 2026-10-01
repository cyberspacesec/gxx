# GXX SDK 使用文档

> 通过可复用的 `*sdk.Engine` 实例进行扫描，构建需要 Go 1.25.0 或更高版本。
> API 设计对标 [nuclei v3](https://github.com/projectdiscovery/nuclei) `NewNucleiEngineCtx` + Functional Options + Callback 模式，并遵循 [Effective Go](https://go.dev/doc/effective_go) 与 [Uber Go 风格指南](https://github.com/uber-go/guide)。

---

## 一、简介

GXX SDK 是 GXX 指纹识别引擎的 Go 库接口。所有对外类型均在 `sdk` 包内定义，调用方无需导入任何内部包。

```go
import "github.com/cyberspacesec/gxx/sdk"
```

运维 / 调试接口在独立子包：

```go
import "github.com/cyberspacesec/gxx/sdk/debug"
```

---

## 二、快速开始

在调用方的 Go 模块中执行：

```bash
go get github.com/cyberspacesec/gxx/sdk@v1.2.0
```

模块路径为 `github.com/cyberspacesec/gxx`，调用方无需配置本地 `replace`。使用 `@latest` 获取当前版本线的最新稳定版本，按当前字段适配调用代码；`FingerInfo.Tags` 为 `[]string`。

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/cyberspacesec/gxx/sdk"
)

func main() {
    ctx := context.Background()

    options, _ := sdk.NewFingerOptions()
    engine, err := sdk.NewEngine(ctx,
        sdk.WithFingerOptions(options),
        sdk.WithTimeout(10*time.Second),
        sdk.WithRuleConcurrency(500),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    result, err := engine.Scan(ctx, "https://example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("URL: %s 状态码: %d 标题: %s\n", result.URL, result.StatusCode, result.Title)
    for _, m := range result.Matches {
        fmt.Printf("  - %s (%s)\n", m.Info.Name, m.Info.ID)
    }
}
```

---

## 三、API 总览

### 3.1 工厂

| 函数 | 说明 |
|------|------|
| `NewEngine(ctx, opts ...Option) (*Engine, error)` | 创建并初始化引擎实例 |
| `NewFingerOptions() (FingerOptions, error)` | 优先探测磁盘 `fingerYaml/`，不存在时使用内置规则；`-tags embed` 的空路径默认库使用内置规则；显式指定路径仍优先 |

### 3.2 Engine 实例方法

| 方法 | 说明 |
|------|------|
| `(*Engine).Scan(ctx, target) (*TargetResult, error)` | 单目标完整指纹识别 |
| `(*Engine).ScanBatch(ctx, targets) ([]*TargetResult, error)` | 批量扫描（一次性返回） |
| `(*Engine).ScanCallback(ctx, targets, cb) error` | 流式批量扫描（回调可取消） |
| `(*Engine).ScanIterator(ctx, targets iter.Seq[string], cb) error` | 按并发预算拉取目标，逐条回调结果 |
| `(*Engine).GetBaseInfo(ctx, target) (*BaseInfo, error)` | 仅获取基础信息（不跑指纹） |
| `(*Engine).WappalyzerScan(ctx, target) (*TechStack, error)` | 仅技术栈识别 |
| `(*Engine).NormalizeURL(ctx, target) (string, error)` | 探测 http/https 协议并返回规范化 URL（遵守 ctx 与 WithTimeout） |
| `(*Engine).LoadFingerOptions(opts) error` | 运行期重新加载指纹规则 |
| `(*Engine).FingerCount() int` | 当前加载的指纹数量 |
| `(*Engine).RuleCatalog(ctx) ([]RuleMetadata, error)` | 全部规则来源、产品目录、检测条件与质量缺项 |
| `ProductCatalog() ([]ProductDefinition, error)` | 内置产品目录的独立副本 |
| `(*Engine).PoolStats() PoolStats` | 规则池统计快照 |
| `(*Engine).ResetPoolStats()` | 重置统计计数 |
| `(*Engine).CacheStats() map[string]any` | 缓存统计快照（含 hit ratio） |
| `(*Engine).MemoryStats() sdk.MemoryStats` | 即时内存快照 |
| `(*Engine).SetMemoryThresholds(high, critical uint64)` | 动态调整内存阈值 |
| `(*Engine).EnableMemoryMonitor(on bool)` | 运行期开关监控 |
| `(*Engine).IsClosed() bool` | 引擎是否已 Close |
| `(*Engine).Close() error` | 释放所有资源（线程安全，可重复调用） |

### 3.3 Functional Options

| Option | 默认值 | 说明 |
|--------|--------|------|
| `WithFingerOptions(opts FingerOptions)` | 空（嵌入式指纹库） | 指纹规则文件 / 目录 |
| `WithMatchDetails(enabled bool)` | `true` | 回传成功子规则与证据，关闭时仍保留产品版本和元数据 |
| `WithProductCatalog(products []ProductDefinition)` | 内置目录 | 实例产品目录，按明确的规则 ID 映射；同一产品 ID 的元数据一致覆盖 |
| `WithRuleAssessments(assessments []RuleAssessment)` | 内置记录 | 按规则 ID 与 SHA256 绑定的测试记录、外部校准置信度 |
| `WithRuleSourceVersion(version string)` | 空 | 外部规则包的来源版本 |
| `WithProxy(addr string)` | `""` | http/https/socks5 代理 |
| `WithTimeout(d time.Duration)` | `10s` | 请求超时（支持亚秒，如 `500*time.Millisecond`） |
| `WithTimeoutSeconds(seconds int)` | — | 请求超时（整秒） |
| `WithInsecureSkipVerify(skip bool)` | `true` | 跳过 TLS 验证 |
| `WithDisableKeepAlives(disable bool)` | `false` | 禁用 HTTP Keep-Alive |
| `WithCustomHeaders(map[string]string)` | nil | 当前实例的请求头，构造时复制 |
| `WithReverseConfig(config ReverseConfig)` | 空配置 | 当前实例的 Ceye / JNDI 反连服务，按值复制 |
| `WithURLConcurrency(n int)` | `5` | 当前实例所有并行扫描共享的 URL 并发上限 |
| `WithRuleConcurrency(n int)` | `200` | 规则并发数 |
| `WithCacheSize(n int)` | `2048` | 请求/响应缓存的目标条目容量 |
| `WithCacheBytes(n int64)` | `64 MiB` | 请求/响应缓存的估算字节预算，超大条目不进入缓存 |
| `WithCacheTTL(d time.Duration)` | `10min` | 缓存 TTL |
| `WithMemoryMonitor(enable bool)` | `false` | 启动内存监控 |
| `WithMemoryThresholds(high, critical uint64)` | 2GB / 4GB | 内存告警阈值 |
| `WithProactiveGC(enable bool)` | `false` | 压力时主动 GC |
| `WithRateLimit(qps float64, burst int)` | 关闭 | per-host 限流 |
| `WithDebug(enable bool)` | `false` | 当前实例的调试日志，不修改全局日志级别 |
| `WithLogger(log *slog.Logger)` | 静默 | 注入实例日志；未注入且开启 Debug 时使用 stderr |
| `WithOutputFile(path string, format OutputFormat)` | 关闭 | 把结果写入本地文件（txt/csv/json，自带异步队列） |
| `WithSockOutputFile(path string)` | 关闭 | 通过 Unix domain socket 实时推送 JSON Lines |
| `WithWriter(w Writer)` | nil | 注入自定义 Writer（可多次调用累加） |

### 3.4 Sentinel Errors

```go
var (
    ErrEmptyTarget       error // 目标 URL 为空
    ErrEngineClosed      error // 引擎已 Close
    ErrEngineNotReady    error // 引擎未就绪
    ErrFingerNotLoaded   error // 指纹库未加载
    ErrScanFailed        error // 扫描失败
    ErrInvalidOption     error // 选项参数非法
    ErrEmptyResult       error // 空结果
    ErrLoadFinger        error // 指纹加载失败
)
```

调用方使用 `errors.Is/As` 判断：

```go
result, err := engine.Scan(ctx, target)
if errors.Is(err, sdk.ErrEngineClosed) {
    // 处理引擎已关闭
}
if errors.Is(err, sdk.ErrEmptyTarget) {
    // 跳过空目标
}
```

---

## 四、核心类型

### TargetResult

```go
type TargetResult struct {
    URL        string        `json:"url"`
    StatusCode int32         `json:"status_code"`
    Title      string        `json:"title"`
    Server     *ServerInfo   `json:"server,omitempty"`
    Matches    []FingerMatch `json:"matches"`
    TechStack  *TechStack    `json:"tech_stack,omitempty"`
    ICP        string        `json:"icp,omitempty"`
    Certs      []CertInfo    `json:"certs,omitempty"`
    Products   []ProductMatch `json:"products,omitempty"`
}
```

### FingerMatch

```go
type FingerMatch struct {
    Info             FingerInfo     `json:"info"`
    Result           bool           `json:"result"`
    Expression       string         `json:"expression"`
    ProductVersion   string         `json:"product_version,omitempty"`
    ProductVersions  []string       `json:"product_versions,omitempty"`
    VersionConflict  bool           `json:"version_conflict,omitempty"`
    DetailsTruncated bool           `json:"details_truncated,omitempty"`
    MatchedRules     []SubRuleMatch `json:"matched_rules,omitempty"`
}
```

### 规则与产品信息

`FingerInfo.Author` 保存规则作者，`Vendor` 来自独立产品目录。`Tags` 为 `[]string`，未知标签不归入 Web。`References` 保存可追溯的 HTTP/HTTPS 产品依据，过滤空值和 `example.com` 占位链接。`Created` 保留规则创建时间。

`Verified` 为 `*bool`：`nil` 表示源 YAML 未声明；`false` 和 `true` 分别表示来源标注未验证、已验证。`VerificationStatus` 使用 `unknown`、`unverified`、`declared-verified`。来源声明与 `Validation` 的样本测试状态独立，不相互替代。`Confidence` 为 `*float64`，默认 JSON `null`；有限合成样本没有经过实际部署数据校准，因此不会赋值为 `1`。

`Source.Path`、`Source.SHA256`、`Source.Version` 保存实际规则来源。内置文件仅在摘要与内置内容一致时使用 SDK 源版本；外部版本由 `WithRuleSourceVersion` 声明。`ProductVersion` 仅来自成功匹配子规则的成功 `output.product_version` 提取，缺失、提取失败或冲突时为空。多个不同版本保留在 `ProductVersions` 并标记 `VersionConflict`。`Server.Version` 是服务响应头信息，不自动用作全部命中产品的版本。

`ProductInfo` 包含目录 ID、规范名称、厂商、分类、标签、别名、参考链接及 CPE。目录 ID 是稳定的 GXX 产品标识，不声称其本身属于其他标准；CPE 仅在有字典依据时填写，产品通配 CPE 不代表检测到漏洞。未知产品不从作者、拼音或规则名猜测厂商与 CPE。

`TargetResult.Matches` 保留每条规则结果；`Products` 按产品目录 ID 归并，并通过 `RuleIDs` 保留来源。没有目录的规则保持独立产品条目，产品 ID 为空，不强行合并。ARL 的两条等价规则保留原始命中，产品展示归并为一个条目。

### 命中证据

`MatchedRules` 包含成功匹配的子规则名称、表达式、请求方法、路径、URL、状态码、输出与 `Evidence`。`FingerMatch.Expression` 保留组合表达式；仅由否定子规则结果组成的匹配允许成功子规则集合为空。每个证据对应实际执行的逻辑分支，不重新执行 CEL、I/O 或随机函数。

证据位置为原字段的字节区间 `[Start, End)`，不是字符索引；`-1` 表示不存在位置或无法准确定位。`Field` 标识 `response.body`、`response.raw_header`、`response.headers.server` 等字段；`SnippetStart` 表示片段起点。UTF-8 内容直接返回，二进制片段使用 `base64`，高亮时先按 `Encoding` 解码。否定条件可返回 `Matched=false` 的缺失证据，不伪造正文位置。动态表达式或不支持定位的计算仍返回表达式与实际布尔结果。

证据使用固定预算：每次表达式最多追踪 128 个布尔节点，成功子规则最多 64 条，每条最多 16 个证据，每个片段最多 256 个原始字节。超出节点或证据数量时设置 `EvidenceTruncated`，超出子规则数量设置 `DetailsTruncated`；片段无法覆盖完整匹配范围时设置证据的 `Truncated`。证据表达式文本最多 512 字节，完整子规则表达式仍可读取。公开输出最多 64 个普通文本或整数项，保留产品版本，单项最多 512 字节；执行变量保留完整值，不通过结果持有完整响应正文。

`WithMatchDetails(false)` 适合无需详情的场景。正文读取维持 512 KiB；favicon 按完整内容流式计算哈希，不采用正文上限。大小写处理、图标哈希算法和实例资源隔离保持相同语义。响应归一化与正则字符缓冲共用每目标 8 MiB 的估算缓存预算。

### 目录导入与扩展

```go
catalog, err := engine.RuleCatalog(ctx)
if err != nil {
    return err
}
for _, rule := range catalog {
    // 按规则 ID 和 SHA256 导入，并独立保存作者、厂商及来源验证声明。
    fmt.Println(rule.Info.ID, rule.Info.Author, rule.Info.Vendor,
        rule.Info.VerificationStatus, rule.Info.Validation, rule.MissingMetadata)
    // Detection 提供子规则条件、传输协议、路径和版本提取表达式。
}
```

`MissingMetadata` 使用 `product-catalog`、`vendor`、`tags`、`references`、`sample-validation`、`version-extractor`，表示待补充数据，不表示规则无效。`Transport` 来自实际子规则请求类型，混合规则使用 `mixed`；HTTP 协议不能替代产品分类。

系统产品目录通过 `WithProductCatalog` 提供 `ProductDefinition`，以 `RuleIDs` 显式关联。目录按产品 ID 统一元数据，多实例独立复制。`WithRuleAssessments` 的记录必须包含方法、样本数、适用范围和规则 SHA256；文件内容变化后旧记录不生效。输入参数与返回的数组、指针可由调用方保存和修改，不影响其他实例。

```go
engine, err := sdk.NewEngine(ctx,
    sdk.WithProductCatalog([]sdk.ProductDefinition{{
        ProductInfo: sdk.ProductInfo{
            ID: "system.product", Name: "产品名称", Vendor: "产品厂商",
            Category: "cms", Tags: []string{"cms"},
        },
        RuleIDs: []string{"rule-id"},
    }}),
    sdk.WithRuleSourceVersion("rules-2026-10-01"),
)
```

目录覆盖与样本测试范围见 [指纹数据与验证](../docs/指纹数据与验证.md)。完整 API 类型以 [`sdk.go`](sdk.go) 和 [`metadata.go`](metadata.go) 为准。

### BaseInfo

```go
type BaseInfo struct {
    Target     string      `json:"target"`
    Title      string      `json:"title"`
    StatusCode int32       `json:"status_code"`
    Server     *ServerInfo `json:"server,omitempty"`
    TechStack  *TechStack  `json:"tech_stack,omitempty"`
    ICP        string      `json:"icp,omitempty"`
    Certs      []CertInfo  `json:"certs,omitempty"`
}
```

### TechStack

```go
type TechStack struct {
    WebServers           []string
    ProgrammingLanguages []string
    WebFrameworks        []string
    JavaScriptFrameworks []string
    JavaScriptLibraries  []string
    Security             []string
    // ... 见 sdk.go
}
```

### FingerOptions

```go
type FingerOptions struct {
    PocFile string // 指纹规则目录路径
    PocYaml string // 单个 YAML 文件路径
}
```

> `FingerOptions` 是 SDK 自有类型，与内部 `types.YamlFingerType` 解耦，调用方无需导入任何内部包。

### TargetCallback

```go
type TargetCallback func(result *TargetResult) bool
```

回调返回 `false` 时取消尚未开始或进行中的后续目标扫描（通过派生 `context` 传播到 `ScanTarget`）。

### Writer / OutputFormat

```go
type Writer interface {
    Write(ctx context.Context, result *TargetResult) error
    Close() error
}

type OutputFormat string

const (
    FormatTXT  OutputFormat = "txt"
    FormatCSV  OutputFormat = "csv"
    FormatJSON OutputFormat = "json"
)
```

每个 Engine 持有独立 Writer（默认 `NopWriter()`），SDK 自带四种实现：
`NopWriter` / `NewFileWriter(path, format)` / `NewSockWriter(path)` / `NewMultiWriter(writers...)`。
通过 `WithOutputFile` / `WithSockOutputFile` / `WithWriter` 注入；Engine 在每个目标
扫描完成后自动派发到 Writer，`Close` 时取消并等待在途扫描，再释放 Runner 并刷新、关闭 Writer。

---

## 五、使用模式

### 5.1 单目标扫描

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

engine, _ := sdk.NewEngine(ctx, sdk.WithTimeout(10*time.Second))
defer engine.Close()

result, err := engine.Scan(ctx, "https://example.com")
```

### 5.2 仅技术栈识别

```go
ts, err := engine.WappalyzerScan(ctx, "https://example.com")
fmt.Println(ts.WebServers, ts.WebFrameworks)
```

### 5.3 流式批量扫描（推荐）

不需要等所有目标完成，逐条出结果：

```go
err := engine.ScanCallback(ctx, []string{"a.com", "b.com", "c.com"}, func(r *sdk.TargetResult) bool {
    fmt.Printf("[%s] matched %d\n", r.URL, len(r.Matches))
    return true // 返回 false 取消整个批次
})
```

### 5.4 一次性批量扫描

```go
results, err := engine.ScanBatch(ctx, targets)
```

### 5.5 多 Engine 并发隔离

每个 `*Engine` 持有独立的指纹库、规则池、请求缓存、HTTP 客户端、CookieJar、图标哈希缓存、反连配置、限流器和监控器，可在同一进程并发存在。第一实例正在扫描时创建、取消或关闭第二实例，不会覆盖第一实例的扫描配置：

```go
engineA, _ := sdk.NewEngine(ctx, sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "fingers_v1"}))
engineB, _ := sdk.NewEngine(ctx, sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "fingers_v2"}))
defer engineA.Close()
defer engineB.Close()

go engineA.Scan(ctx, "...")
go engineB.Scan(ctx, "...")
```

请求头在构造时复制，反连配置按值传递，YAML 的规则顺序解析使用当前调用的状态。CEL 编译程序、只读技术栈索引和独占借用的对象池可以在进程内复用；Go 堆、GC 和内存统计属于整个进程。不同操作系统进程的 Go 变量与堆天然独立。

反连服务通过实例选项配置：

```go
engine, err := sdk.NewEngine(ctx,
    sdk.WithReverseConfig(sdk.ReverseConfig{
        CeyeAPIKey: "your-api-key",
        CeyeDomain: "your-domain.ceye.io",
        JNDIHost: "reverse.example.com",
        LDAPPort: "1389",
        APIPort: "8080",
    }),
)
if err != nil { return err }
defer engine.Close()
```

### 5.6 per-host 限流

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithRateLimit(50, 100), // 50 QPS，桶大小 100
)
```

每个目标 host 持有独立的令牌桶（基于 `golang.org/x/time/rate`），对实际 HTTP 请求计数，包括基础探测、规则请求、图标、重定向和重试。

### 5.7 内存监控

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithMemoryMonitor(true),
    sdk.WithMemoryThresholds(2<<30, 4<<30), // 2GB / 4GB
    sdk.WithProactiveGC(false),             // 仅告警，不触发 STW
)

// 任意时间点取快照
stats := engine.MemoryStats()
fmt.Printf("HeapAlloc=%d GoSchedLatency=%.3fms\n",
    stats.HeapAlloc, stats.GoSchedLatency*1000)
```

监控结合 `runtime/metrics` 和 `runtime.ReadMemStats`，提供堆、GC 和调度延迟统计。数据属于整个 Go 进程，包括其他 Engine 和共享缓存，并非单个 Engine 的独占内存；阈值是调节并发的依据，不是 RSS 硬上限。

### 5.8 输出到文件 / Socket / 自定义 Writer

SDK 自带实例化 `Writer` 抽象，每个 Engine 管理自己的写入器。调用方若为不同 Engine 传入同一个自定义 Writer、Logger，或相同输出文件与 Socket 路径，外部资源会被共享，需要由调用方管理其并发和生命周期。

```go
engine, _ := sdk.NewEngine(ctx,
    // 写入 JSON Lines（每行一条结果）
    sdk.WithOutputFile("results.json", sdk.FormatJSON),
    // 同时广播到 Unix socket
    sdk.WithSockOutputFile("/tmp/gxx.sock"),
    // 还可以叠加自定义 Writer（Kafka、Webhook 等）
    sdk.WithWriter(myKafkaWriter),
)
defer engine.Close()
```

Writer 接口非常简单，调用方可自行实现：

```go
type Writer interface {
    Write(ctx context.Context, result *TargetResult) error
    Close() error
}
```

内置实现：

| 工厂 | 说明 |
|------|------|
| `NopWriter()` | 不写任何内容（默认） |
| `NewFileWriter(path, format)` | 写入本地文件，支持 `FormatTXT` / `FormatCSV` / `FormatJSON`，内置 1024 容量异步队列，溢出回退同步 |
| `NewSockWriter(path)` | 监听 Unix domain socket，向所有连接广播 JSON Lines |
| `NewMultiWriter(writers...)` | 把多个 Writer 串联，错误用 `errors.Join` 收集 |

> Writer 的同步写入错误交给实例日志，不改变 `Scan` 的返回值。内置文件 Writer 的异步写入和刷新错误由 `Close` 返回，调用方应检查关闭错误；自定义 Writer 负责自己的错误策略。
> 文件 Writer 入队时复制结果，调用方之后修改结果不会改变待写入数据。

### 5.9 自定义指纹库

```go
engine, _ := sdk.NewEngine(ctx, sdk.WithFingerOptions(sdk.FingerOptions{
    PocFile: "/path/to/custom/fingers", // 目录
}))

// 或者运行期切换
engine.LoadFingerOptions(sdk.FingerOptions{PocYaml: "single.yaml"})
```

---

## 六、并发安全 / 生命周期

### 6.1 安全保证

| 操作 | 并发安全 | 说明 |
|------|---------|------|
| `NewEngine` | ✅ | 每次调用返回独立实例 |
| `(*Engine).Scan` / `ScanBatch` / `ScanCallback` / `ScanIterator` | ✅ | 同一 Engine 多 goroutine 调用安全 |
| `(*Engine).GetBaseInfo` / `WappalyzerScan` | ✅ | 同上 |
| `(*Engine).Close` | ✅ | 可重复调用，多次 Close 无副作用 |
| `(*Engine).LoadFingerOptions` | ✅ | 加载成功后整体发布规则快照；失败保留原库，在途扫描继续使用原快照 |
| 多个 Engine 并发 | ✅ | 每个实例隔离，互不影响 |

### 6.2 生命周期

```
NewEngine(opts...)
  ├─ runner.NewRunner(scanCfg, fingers)  // 构造独立 Runner 实例
  └─ 返回 *Engine（持有 *runner.Runner）

(*Engine).Scan(ctx, target)
  └─ runner.ScanTarget(ctx, target)     // ctx 取消会中止规则请求

(*Engine).Close
  ├─ 拒绝新操作，取消并等待在途扫描和结果交付
  ├─ runner.Close：停止监控、释放规则池、缓存和空闲连接
  └─ Writer.Close：排空已接收的文件输出并关闭 Writer
```

### 6.3 必须 defer Close

`Engine` 持有 ants 协程池、otter 后台 goroutine 和可选的监控 ticker，应在不再使用时调用 `Close()`。

同一次 `ScanCallback` 或 `ScanIterator` 的回调串行执行，不同调用之间的回调可并发。回调返回 `false` 取消该批次；不要在回调或自定义 `Writer.Write` 内同步调用同一 Engine 的 `Close`，否则会等待当前操作自身。自定义 Writer 应响应传入的 context。批量扫描保留成功结果，同时返回目标失败的聚合错误；取消错误可通过 `errors.Is` 判断。

`ScanIterator` 接受 Go 标准库的 `iter.Seq[string]`，无需先构造完整目标切片。迭代器必须在 `yield` 返回 `false` 时停止，阻塞输入源的取消由调用方负责。引擎最多提前拉取一个等待并发名额的目标，不保存已消费的成功结果；失败信息仍会聚合，因此错误数量很大时也会占用内存。

```go
scanner := bufio.NewScanner(reader) // reader 为调用方持有的 io.Reader
targets := func(yield func(string) bool) {
    for scanner.Scan() {
        target := strings.TrimSpace(scanner.Text())
        if target != "" && !yield(target) {
            return
        }
    }
}
err := engine.ScanIterator(ctx, targets, func(result *sdk.TargetResult) bool {
    fmt.Println(result.Target, result.Title)
    return true
})
if err == nil {
    err = scanner.Err()
}
```

---

## 七、调试 / 运维 API（`gxx/sdk/debug`）

```go
import (
    "github.com/cyberspacesec/gxx/sdk"
    "github.com/cyberspacesec/gxx/sdk/debug"
)

engine, _ := sdk.NewEngine(ctx, sdk.WithMemoryMonitor(true))
defer engine.Close()

stats := debug.MemoryStatsOf(engine)
fmt.Printf("HeapAlloc=%dMB NumGC=%d\n", stats.HeapAlloc>>20, stats.NumGC)

debug.ForceGC()

rl := debug.HostRateLimiterStatsOf(engine)
fmt.Printf("enabled=%v cached_hosts=%d qps=%.1f\n", rl.Enabled, rl.CachedHosts, rl.QPS)
```

> v3 移除了 `StartMemoryMonitor` / `StopMemoryMonitor` / `SetMemoryThresholds` 等包级函数。
> 这些功能改由 `sdk.NewEngine(...)` 时通过 `sdk.WithMemoryMonitor(true)` / `sdk.WithMemoryThresholds(...)` 注入，并由 `(*Engine).Close()` 自动清理。

---

## 八、示例项目

完整示例位于 `example/` 目录：

| 目录 | 演示内容 |
|------|---------|
| `example/basic_scan/` | 基本单目标扫描 + functional options |
| `example/api_scan_baidu/` | API 调用 + sentinel error 处理 |
| `example/file_target_scan/` | 从文件批量扫描 + ScanCallback 流式回调 |
| `example/proxy_scan/` | 通过代理扫描 + per-host 限流 |
| `example/wappalyzer_scan/` | 多目标技术栈识别（同 Engine 复用） |
| `example/output_writer/` | `WithOutputFile` JSON Lines + 自定义 Writer（计数 / Kafka / Webhook） |

---

## 九、迁移指南（v2 → v3）

| v2 包级 API | v3 替代 |
|-------------|---------|
| `sdk.InitFingerRules(opts)` | `sdk.NewEngine(ctx, sdk.WithFingerOptions(opts))` |
| `sdk.EnsureFingerRulesLoaded()`（已移除） | `NewEngine` 在指纹路径为空时自动加载嵌入式库 |
| `sdk.FingerScan(ctx, target, proxy, timeout)` | `(*Engine).Scan(ctx, target)`（proxy/timeout 走 Option）|
| `sdk.GetBaseInfo(ctx, target, proxy, timeout)` | `(*Engine).GetBaseInfo(ctx, target)` |
| `sdk.WappalyzerScan(ctx, target, proxy, timeout)` | `(*Engine).WappalyzerScan(ctx, target)` |
| `sdk.NormalizeURL(target, proxy)` | `(*Engine).NormalizeURL(ctx, target)`（proxy/timeout 走 Option） |
| `sdk.GetPoolStats()` | `(*Engine).PoolStats()` |
| `sdk.ResetPoolStats()` | `(*Engine).ResetPoolStats()` |
| `sdk.GetCacheStats()` | `(*Engine).CacheStats()` |
| `sdk.GetDefaults()` | 已删除（不再暴露内部默认值，需要时直接读 Option 注释） |
| `debug.StartMemoryMonitor()` / `StopMemoryMonitor()` | `sdk.WithMemoryMonitor(true)` 在 NewEngine 启用 |
| `debug.SetMemoryThresholds(...)` | `sdk.WithMemoryThresholds(...)` 在 NewEngine 启用 |
| `debug.EnableProactiveGC(...)` | `sdk.WithProactiveGC(...)` 在 NewEngine 启用 |
| `debug.SetDisableKeepAlives(...)` | `sdk.WithDisableKeepAlives(...)` 在 NewEngine 启用 |

> v3 完全移除上述老 API，编译期会报 undefined。请按表格直接迁移。

---

## 十、注意事项

- 所有扫描 API 第一个参数是 `context.Context`，支持超时与取消（透传给底层 HTTP 客户端 + per-host 限流 Wait）
- SDK 内部已实现请求缓存、对象池、并发控制、限流、监控，调用方无需额外管理
- 长期复用 Engine；大批量任务使用 `ScanCallback` 及时消费结果，输入也需要流式读取时使用 `ScanIterator`，避免把所有目标和响应保留在切片中
- 按 CPU、目标延迟和响应大小配置并发，资源受限时可从 URL 并发 2、规则并发 32、缓存 16 MiB 开始测量；这些设置不裁剪规则，但可能增加排队时间
- 请求缓存使用异步淘汰，字节预算是估算容量；不同扫描的缓存作用域互相隔离，并共享实例容量预算。同次扫描内可缓存的相同普通 GET 合并执行，清理只影响所属扫描
- 静态规则快照持有连续的不可变执行清单；仅依赖已缓存首页且没有动态声明、循环或等待的指纹可按最多 8 条合并调度，每条独立评估、计数和处理异常。其他指纹按单条任务执行，规则并发与在途指纹预算保持不变；求值状态归还时清除响应和其他扫描状态，循环、I/O 和等待函数保留取消约束
- 引擎内部构造的响应按只读所有权共享；公共缓存写入复制调用方的完整消息，超过字节预算时跳过缓存，不生成被裁剪的缓存响应。实例请求头在构造时复制，规则覆盖头只作用于对应请求
- 标题解析直接消费只读正文的字节视图；标题与 ICP 备案号独立持有返回字符串，长期保留结果不会通过这些字段引用整页 HTML 或脚本。无候选的合法 UTF-8 正文无需为备案号解析复制整页；结果数量增长仍会增加内存
- favicon 哈希使用 1,824 字节原始块和 2,465 字节编码块读取到 EOF，不构造完整图片或 Base64 副本；入口页支持非根路径、重定向、多个候选与内联图片。成功哈希归当前实例持有，按请求头和 Cookie 会话隔离，候选回退共用时间预算；同一组图片字节的哈希编码约定不变。元数据识别范围与限制见 [网站元数据识别](../docs/网站元数据识别.md)
- 未知长度响应使用 32 KiB 暂存块，暂存池最多保留 1 MiB，最终正文使用独立数组；已知长度响应采用有界容量提示，两条路径保持相同的正文上限和读取错误语义
- 页面正文上限为 512 KiB；图标不受该资源大小限制，使用固定块读取到 EOF。内联图标声明仍需包含在已读取的页面正文中

- 大响应的重复字节包含查询可使用按需构造的 8 KiB 片段位图。候选仍调用原始包含函数，位图饱和、响应太小或复用次数不足时使用直接匹配；相关响应数据共用单次扫描 8 MiB 的估算预算
- 技术栈识别按响应字段建立索引，正文通过必要字面量索引筛选候选；全部 HTTP 规则保持可用，候选由上游解析器判定。编译正则按 512 条工作集共享缓存，淘汰后可重新编译，不裁剪规则；覆盖大量不同模式的负载可能增加编译开销
- CLI 输出完成后只保留汇总计数，不保留全量结果；目标去重集合仍随唯一目标数增长
- 不要用每目标强制 GC 控制内存；RSS 还包括 Go 运行时保留页、线程栈和原生组件，通常高于存活堆
- 所有对外类型均在 `sdk` 包内定义，**不需要**导入 `gxx/types` 或 `gxx/pkg/*` 等内部包

读取策略、实例归属和验证记录见[资源读取与实例隔离](../docs/资源读取与实例隔离.md)。
