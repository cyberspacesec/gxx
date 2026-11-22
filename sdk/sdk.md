# GXX SDK 使用文档

> 通过可复用的 `*sdk.Engine` 实例进行扫描，构建需要 Go 1.27.0 或更高版本。
> API 设计对标 [nuclei v3](https://github.com/projectdiscovery/nuclei) `NewNucleiEngineCtx` + Functional Options + Callback 模式，并遵循 [Effective Go](https://go.dev/doc/effective_go) 与 [Uber Go 风格指南](https://github.com/uber-go/guide)。

---

## 一、简介

GXX SDK 是 GXX 指纹识别引擎的 Go 库接口。所有对外类型均在 `sdk` 包内定义，调用方无需导入任何内部包。

```go
import "github.com/cyberspacesec/gxx/sdk"
```

---

## 二、快速开始

在调用方的 Go 模块中执行：

```bash
go get github.com/cyberspacesec/gxx/sdk@v1.8.0
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
| `(*Engine).ScanWith(ctx, target, opts ...ScanOption) (*TargetResult, error)` | 同 `Scan`，并应用本次扫描的网络策略、求值报告与交换观察；不带选项时与 `Scan` 完全一致 |
| `(*Engine).DebugRule(ctx, target, ruleID, opts ...ScanOption) (*RuleDebug, error)` | 按扫描的方式只执行一条规则，返回每条子规则的结果、交换、证据、输出与失败原因 |
| `(*Engine).ScanBatch(ctx, targets) ([]*TargetResult, error)` | 批量扫描（一次性返回） |
| `(*Engine).ScanCallback(ctx, targets, cb) error` | 流式批量扫描（回调可取消） |
| `(*Engine).ScanIterator(ctx, targets iter.Seq[string], cb) error` | 按并发预算拉取目标，逐条回调结果 |
| `(*Engine).GetBaseInfo(ctx, target) (*BaseInfo, error)` | 仅获取基础信息（不跑指纹） |
| `(*Engine).WappalyzerScan(ctx, target) (*TechStack, error)` | 仅技术栈识别 |
| `(*Engine).NormalizeURL(ctx, target) (string, error)` | 确定目标所属的资产地址：已带协议时原样返回，否则请求一次入口确定 http/https |
| `(*Engine).LoadFingerOptions(opts) error` | 运行期重新加载指纹规则 |
| `(*Engine).FingerCount() int` | 当前加载的指纹数量 |
| `(*Engine).RuleCatalog(ctx) ([]RuleMetadata, error)` | 全部规则来源、产品与服务声明、检测条件与质量缺项 |
| `ProductCatalog() ([]ProductDefinition, error)` | 内置产品目录的独立副本，由内置规则的产品声明生成 |
| `ValidateRule(content []byte, opts ValidateOptions) []Diagnostic` | 不发请求校验一条规则，结论与 `NewEngine` 加载一致 |
| `(*Engine).PoolStats() PoolStats` | 规则池统计快照 |
| `(*Engine).IsClosed() bool` | 引擎是否已 Close |
| `(*Engine).Close() error` | 释放所有资源（线程安全，可重复调用） |

### 3.3 Functional Options

| Option | 默认值 | 说明 |
|--------|--------|------|
| `WithFingerOptions(opts FingerOptions)` | 空（嵌入式指纹库） | 指纹规则文件 / 目录 |
| `WithMatchDetails(enabled bool)` | `true` | 回传成功子规则与证据，关闭时仍保留产品版本和元数据 |
| `WithProductCatalog(products []ProductDefinition)` | 规则自带声明 | 按规则 ID 追加或覆盖产品声明；同一规则被两个目录项声明时报错 |
| `WithRuleAssessments(assessments []RuleAssessment)` | 内置记录 | 按规则 ID 与 SHA256 绑定的测试记录、外部校准置信度 |
| `WithRuleSourceVersion(version string)` | 空 | 外部规则包的来源版本 |
| `WithProxy(addr string)` | `""` | 单个代理地址：http/https/socks5/socks5h（socks4/socks4a 仅 TCP）。UDP 规则仅 socks5/socks5h。证书默认不校验（含 TLS 代理）；TLS 代理可用 `?tls-insecure-skip-verify=false` 开启校验，`tls-ca-file`/`tls-domain` 指定信任根与校验名 |
| `WithTimeout(d time.Duration)` | `10s` | 请求超时（支持亚秒，如 `500*time.Millisecond`） |
| `WithInsecureSkipVerify(skip bool)` | `true` | 是否跳过**目标**证书校验（默认跳过）；代理证书校验由代理地址的查询参数单独控制 |
| `WithDisableKeepAlives(disable bool)` | `false` | 禁用 HTTP Keep-Alive |
| `WithCustomHeaders(map[string]string)` | nil | 当前实例的请求头，构造时复制 |
| `WithReverseConfig(config ReverseConfig)` | 空配置 | 当前实例的 Ceye / JNDI 反连服务，按值复制 |
| `WithURLConcurrency(n int)` | `5` | 当前实例所有并行扫描共享的 URL 并发上限 |
| `WithRuleConcurrency(n int)` | `200` | 规则并发数 |
| `WithCacheSize(n int)` | `2048` | 请求/响应缓存的目标条目容量 |
| `WithCacheTTL(d time.Duration)` | `10min` | 缓存 TTL |
| `WithMemoryMonitor(enable bool)` | `false` | 启动内存监控 |
| `WithMemoryThresholds(high, critical uint64)` | 2GB / 4GB | 内存告警阈值 |
| `WithProactiveGC(enable bool)` | `false` | 压力时主动 GC |
| `WithGlobalRateLimit(perSecond float64, burst int)` | 关闭 | 引擎全部请求的总速率上限（次/秒） |
| `WithGlobalRatePerMinute(perMinute int)` | 关闭 | 同上，按每分钟请求数设置，匀速发出 |
| `WithRateLimit(qps float64, burst int)` | 关闭 | 每主机限速；主机按主机名或 IP 区分，不区分端口 |
| `WithRateLimitPerPort(enable bool)` | `false` | 每主机限速改为按“主机:端口”分别计算 |
| `WithDebug(enable bool)` | `false` | 当前实例的调试日志，不修改全局日志级别 |
| `WithLogger(log *slog.Logger)` | 静默 | 注入实例日志；未注入且开启 Debug 时使用 stderr |
| `WithOutputFile(path string, format OutputFormat)` | 关闭 | 把结果写入本地文件（txt/csv/json，自带异步队列） |
| `WithWriter(w Writer)` | nil | 注入自定义 Writer（可多次调用累加） |
| `WithNetworkPolicy(policy NetworkPolicy)` | 无 | 引擎级网络策略：`Dial`、`CheckTarget`、`Redirect`、`WrapTransport`，见 [网络策略](../docs/网络策略.md) |
| `WithRuleFS(fsys fs.FS, root string)` | 无 | 从文件系统（内存文件系统、`embed.FS`）的 `root` 目录加载规则，不能与 `WithFingerOptions` 的目录或文件同时使用 |
| `WithRulePolicy(policy RulePolicy)` | 不限制 | 限制可加载的规则类型、Raw、反连、sleep、规则数与子规则数，违反即加载失败 |
| `WithBodyLimit(n int64)` | `512 KiB` | 响应正文读取上限 |
| `WithCacheMaxBytes(n int64)` | `64 MiB` | 请求/响应缓存的字节预算 |
| `WithResponseCacheBudget(n int64)` | `8 MiB` | 每次扫描的响应归一化缓存预算 |
| `WithIconEvidence(maxData int)` | 关闭 | 在 `TargetResult.Icon` 记录最终页面图标的证据，原始字节最多 `maxData` |
| `WithJARM(enable bool)` | `false` | 为 HTTPS 目标计算 JARM 指纹，见 [TLS 信息与指纹](../docs/TLS信息与指纹.md) |
| `WithResources(opts ResourceOptions)` | 全关 | 读取最终页面所在资产的 robots.txt 与 sitemap.xml，见 [附属资源](../docs/附属资源.md) |

`ScanWith` 与 `DebugRule` 接受的扫描级选项：

| ScanOption | 说明 |
|------------|------|
| `ScanNetworkPolicy(policy NetworkPolicy)` | 本次扫描的网络策略，逐字段覆盖引擎级策略 |
| `ScanEvaluationReport(dst *EvaluationReport)` | 扫描结束后（含失败与取消）把求值报告写入 `dst` |
| `ScanObserver(observe func(Exchange), limits ExchangeLimits)` | 每次交换完成后串行回调 |

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
    ErrRulePolicy        error // 规则违反 WithRulePolicy；errors.As 取 *RulePolicyError
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

扫描类方法（`Scan` / `ScanBatch` / `ScanCallback` / `ScanIterator` / `GetBaseInfo` / `WappalyzerScan` / `NormalizeURL`）的目标失败错误统一包装 `ErrScanFailed`，底层原因用 `errors.Join` 附加，可用 `errors.Is(err, sdk.ErrScanFailed)` 统一判定。`ScanIterator` / `ScanCallback` 聚合各目标错误，条数上限 100，超出仅计数并追加一条截断汇总，避免大批量失败时错误链无界增长。引擎在扫描在途时被 `Close`，返回的是 context 取消错误（`context.Canceled`）而非 `ErrEngineClosed`——两者都表示应停止。

---

## 四、核心类型

### TargetResult

```go
type TargetResult struct {
    URL        string        `json:"url"`
    FinalURL   string        `json:"final_url,omitempty"`   // 跳转链最后一页的地址
    RedirectTo string        `json:"redirect_to,omitempty"` // 页面里识别出的、未跟随的跨资产跳转
    Redirects  []Redirect    `json:"redirects,omitempty"`   // 入口跳转链
    StatusCode int32         `json:"status_code"`
    Title      string        `json:"title"`
    Server     *ServerInfo   `json:"server,omitempty"`
    Headers    string        `json:"headers,omitempty"`     // 最后一页的原始响应头
    Matches    []FingerMatch `json:"matches"`
    TechStack  *TechStack    `json:"tech_stack,omitempty"`
    ICP        string        `json:"icp,omitempty"`
    Certs      []CertInfo    `json:"certs,omitempty"`
    Products   []ProductMatch `json:"products,omitempty"`
    HeaderOrder []string      `json:"header_order,omitempty"` // 最后一页的响应头名称，按服务器顺序
    TLS        *TLSInfo       `json:"tls,omitempty"`          // 最后一页所在连接的 TLS 摘要
    Icon       *IconEvidence  `json:"icon,omitempty"`         // WithIconEvidence 时的图标证据
    Resources  []Resource     `json:"resources,omitempty"`    // WithResources 时的附属资源
}
```

`Headers` 按服务器发送的顺序逐行写出最后一页的响应头（名称为规范形式，多值头各占一行），无法记录顺序时按名称排序；`HeaderOrder` 保留原始大小写与重复的名称。

### Redirect

```go
type Redirect struct {
    Type     string `json:"type"`             // http / refresh / javascript
    Status   int32  `json:"status,omitempty"` // 发出跳转的响应的状态码
    From     string `json:"from"`
    To       string `json:"to"`
    Followed bool   `json:"followed"`         // false：页面里识别出的跳转指向其他资产，没有访问
}
```

`StatusCode`、`Title`、`TechStack`、`ICP`、`Headers` 描述 `FinalURL` 对应的页面。`BaseInfo` 带有相同的 `FinalURL`、`RedirectTo`、`Redirects` 字段。

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

```go
type FingerInfo struct {
    ID                 string         `json:"id"`
    Name               string         `json:"name"`
    Author             string         `json:"author,omitempty"`
    Severity           string         `json:"severity,omitempty"`
    Description        string         `json:"description,omitempty"`
    Tags               []string       `json:"tags,omitempty"`
    Vendor             string         `json:"vendor,omitempty"`
    Verified           *bool          `json:"verified"`
    VerificationStatus string         `json:"verification_status"`
    Confidence         *float64       `json:"confidence"`
    References         []string       `json:"references,omitempty"`
    Created            string         `json:"created,omitempty"`
    Source             RuleSource     `json:"source"`
    Product            *ProductInfo   `json:"product,omitempty"`
    Validation         ValidationInfo `json:"validation"`
    Services           []Service      `json:"services,omitempty"` // 规则声明的 TCP/UDP 服务
    Metadata           map[string]any `json:"metadata,omitempty"` // info.metadata 的副本，只透传
}

type ProductInfo struct {
    ID          string   `json:"id"`                 // 厂商段.产品段
    Name        string   `json:"name"`
    Vendor      string   `json:"vendor,omitempty"`
    Category    string   `json:"category,omitempty"`
    Identity    string   `json:"identity,omitempty"`  // product / signal
    Assurance   string   `json:"assurance,omitempty"` // verified / inferred
    Tags        []string `json:"tags,omitempty"`
    Aliases     []string `json:"aliases,omitempty"`
    CPE         []string `json:"cpe,omitempty"`
    References  []string `json:"references,omitempty"`
    Description string   `json:"description,omitempty"`
}

type Service struct {
    Protocol  string `json:"protocol"`
    Transport string `json:"transport"` // tcp / udp
    Ports     []int  `json:"ports,omitempty"`
}
```

`FingerInfo.Author` 保存规则作者，`Vendor` 等于产品声明的厂商。`Tags` 为 `[]string`，合并规则标签与产品标签，未知标签不归入 Web。`References` 合并规则引用与产品参考链接，保存可追溯的 HTTP/HTTPS 依据，过滤空值、含账号信息的链接和 `example.com` 占位链接。`Created` 保留规则创建时间。`Services` 与 `Metadata` 来自规则的 `info.services`、`info.metadata`，每次返回独立副本。

`Verified` 为 `*bool`：`nil` 表示源 YAML 未声明；`false` 和 `true` 分别表示来源标注未验证、已验证。`VerificationStatus` 使用 `unknown`、`unverified`、`declared-verified`。来源声明与 `Validation` 的样本测试状态独立，不相互替代。`Confidence` 为 `*float64`，默认 JSON `null`；有限合成样本没有经过实际部署数据校准，因此不会赋值为 `1`。

`Source.Path`、`Source.SHA256`、`Source.Version` 保存实际规则来源。内置文件仅在摘要与内置内容一致时使用 SDK 源版本；外部版本由 `WithRuleSourceVersion` 声明。`ProductVersion` 仅来自成功匹配子规则的成功 `output.product_version` 提取，缺失、提取失败或冲突时为空。多个不同版本保留在 `ProductVersions` 并标记 `VersionConflict`。`Server.Version` 是服务响应头信息，不自动用作全部命中产品的版本。

`ProductInfo` 来自规则自带的 `info.product` 声明（字段规则见[指纹规则格式说明](../docs/指纹规则格式说明.md#产品声明)），`WithProductCatalog` 可以按规则 ID 覆盖。产品 ID 是稳定的 GXX 产品标识，不声称其本身属于其他标准。`Identity` 为 `product` 表示命中即确认是这个产品，`signal` 表示技术线索（语言、前端库、默认页面、只能识别出厂商的页面、通用特征）；`Assurance` 为 `verified` 表示厂商与产品已确认且有可访问的官方链接，`inferred` 表示由规则名称与特征推断，调用方可据此决定是否直接展示。CPE 仅在有字典依据时填写，产品通配 CPE 不代表检测到漏洞；声明中无效的参考链接与 CPE 不进入结果。未声明产品的规则 `Product` 为 `nil`，不从作者、拼音或规则名猜测厂商与 CPE。

`TargetResult.Matches` 保留每条规则结果；`Products` 按产品 ID 归并，并通过 `RuleIDs` 保留来源。未声明产品的规则保持独立产品条目，产品 ID 为空，不强行合并。同一产品 ID 在规则集中的有效声明必须完全一致，加载（含 `LoadFingerOptions`）时检查，不一致返回可用 `errors.As` 取得的 `*ProductConflictError`。

### 命中证据

`MatchedRules` 包含成功匹配的子规则名称、表达式、请求方法、路径、URL、状态码、输出与 `Evidence`。`FingerMatch.Expression` 保留组合表达式；仅由否定子规则结果组成的匹配允许成功子规则集合为空。每个证据对应实际执行的逻辑分支，不重新执行 CEL、I/O 或随机函数。

证据位置为原字段的字节区间 `[Start, End)`，不是字符索引；`-1` 表示不存在位置或无法准确定位。`Field` 标识 `response.body`、`response.raw_header`、`response.headers.server` 等字段；`SnippetStart` 表示片段起点。UTF-8 内容直接返回，二进制片段使用 `base64`，高亮时先按 `Encoding` 解码。否定条件可返回 `Matched=false` 的缺失证据，不伪造正文位置。动态表达式或不支持定位的计算仍返回表达式与实际布尔结果。

证据使用固定预算：每次表达式最多追踪 128 个布尔节点，成功子规则最多 64 条，每条最多 16 个证据，每个片段最多 256 个原始字节。超出节点或证据数量时设置 `EvidenceTruncated`，超出子规则数量设置 `DetailsTruncated`；片段无法覆盖完整匹配范围时设置证据的 `Truncated`。证据表达式文本最多 512 字节，完整子规则表达式仍可读取。公开输出最多 64 个普通文本或整数项，保留产品版本，单项最多 512 字节；执行变量保留完整值，不通过结果持有完整响应正文。

`WithMatchDetails(false)` 适合无需详情的场景。正文读取默认 512 KiB（`WithBodyLimit` 设置）；favicon 按完整内容流式计算哈希，不采用正文上限。大小写处理、图标哈希算法和实例资源隔离保持相同语义。响应归一化与正则字符缓冲共用每目标的估算缓存预算（默认 8 MiB，`WithResponseCacheBudget` 设置）。

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

`MissingMetadata` 按顺序使用以下取值（常量 `sdk.Missing*`），表示待补充或待核实的数据，不表示规则无效：`product`（没有产品声明，也没有目录覆盖）、`vendor`（产品没有厂商）、`product-assurance`（产品信息为推断）、`tags`（规则与产品都没有标签）、`references`（没有有效参考链接）、`services`（TCP/UDP 规则没有声明服务）、`sample-validation`（没有绑定当前规则内容的专项样本记录）、`version-extractor`（没有 `product_version` 输出）。`Transport` 来自实际子规则请求类型，混合规则使用 `mixed`；HTTP 协议不能替代产品分类。

内置产品目录 `ProductCatalog()` 由内置规则的产品声明生成（`sdk/catalog.json`，`go generate ./sdk` 重新生成），每个产品列出声明它的全部规则 ID。系统产品目录通过 `WithProductCatalog` 提供 `ProductDefinition`，按 `RuleIDs` 逐条追加（规则没有声明时）或覆盖（规则已有声明时）产品信息，未列出的规则保留自带声明；同一规则出现在两个目录项中返回 `ErrInvalidOption`。覆盖一个已有产品 ID 时应列出该产品的全部规则，否则同一产品的声明不一致，加载失败。多实例独立复制。`WithRuleAssessments` 的记录必须包含方法、样本数、适用范围和规则 SHA256；文件内容变化后旧记录不生效。输入参数与返回的数组、指针可由调用方保存和修改，不影响其他实例。

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
    Target      string        `json:"target"`
    FinalURL    string        `json:"final_url,omitempty"`
    RedirectTo  string        `json:"redirect_to,omitempty"`
    Redirects   []Redirect    `json:"redirects,omitempty"`
    Title       string        `json:"title"`
    StatusCode  int32         `json:"status_code"`
    Server      *ServerInfo   `json:"server,omitempty"`
    TechStack   *TechStack    `json:"tech_stack,omitempty"`
    ICP         string        `json:"icp,omitempty"`
    Certs       []CertInfo    `json:"certs,omitempty"`
    HeaderOrder []string      `json:"header_order,omitempty"`
    TLS         *TLSInfo      `json:"tls,omitempty"`
    Icon        *IconEvidence `json:"icon,omitempty"`
    Resources   []Resource    `json:"resources,omitempty"`
}
```

### TLSInfo / IconEvidence / Resource

```go
type TLSInfo struct {
    Version     string `json:"version"`        // 如 "TLS 1.2"
    CipherSuite string `json:"cipher_suite"`   // 如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ALPN        string `json:"alpn,omitempty"` // 扫描的 ClientHello 不携带 ALPN，通常为空
    JA3S        string `json:"ja3s,omitempty"`
    JARM        string `json:"jarm,omitempty"` // WithJARM(true) 时计算
}

type IconEvidence struct {
    URL, ContentType string
    Bytes            int64
    SHA256, MMH3     string // MMH3 与 response.icon_hash 相同
    Data             []byte // 不超过 WithIconEvidence 的上限，超过时为空并置 TooLarge
    TooLarge         bool
    CrossOrigin      bool   // 图标与页面不属于同一资产
}

type Resource struct {
    Kind       string // robots / sitemap
    URL        string
    StatusCode int
    Body       []byte // 前 MaxBytes 字节
    BodyBytes  int64  // 实际读取的正文字节数
    SHA256     string // 实际读取的正文的摘要
    Truncated  bool
}
```

TLS 版本、套件、ALPN 与 JA3S 取自扫描已有的那次握手，不增加连接；图标证据来自计算 `icon_hash` 的同一次请求，不二次请求。详见 [TLS 信息与指纹](../docs/TLS信息与指纹.md) 与 [附属资源](../docs/附属资源.md)。

### EvaluationReport

```go
type EvaluationReport struct {
    Complete  bool             // 全部规则都已执行且没有任何失败
    Rules     []RuleEvaluation // 按规则标识排序
    Truncated bool             // 记录超出上限而被省略
}

type RuleEvaluation struct {
    RuleID, SourceSHA256 string
    Completed, Matched   bool
    Failures             []EvaluationFailure
}

type EvaluationFailure struct {
    RuleID, SubRule string
    Stage           FailureStage // request expression non_bool extract regex_timeout panic budget
    Message         string       // 不超过 256 字节，不含响应正文
}
```

求值报告只说明结论是否完整，不改变普通匹配语义：`Matches` 与不带报告的扫描相同。各阶段的含义：

| Stage | 含义 |
|---|---|
| `request` | 子规则的请求失败（含被网络策略拒绝）；入口不可达时未执行的 HTTP 规则也记为 `request` |
| `expression` | 表达式运行错误（如取不存在的键） |
| `non_bool` | 子规则或总表达式的结果不是布尔值 |
| `extract` | `output` 提取表达式求值失败 |
| `regex_timeout` | 正则匹配超过 250ms，按未命中处理 |
| `panic` | 规则执行中 panic，只影响该规则 |
| `budget` | 使用了被正文上限截断的响应、表达式超出计算成本上限，或单条规则的失败超过 16 条 |

扫描被取消、入口失败或记录超出上限（每条规则 16 条失败、每次扫描 65,536 条规则）时 `Complete` 为 `false`。

### Exchange

```go
type Exchange struct {
    Sequence            int         // 按回调顺序从 1 递增
    Kind                RequestKind // http raw tcp udp icon resource tls
    RuleID, SubRule     string      // 规则请求时为所属规则
    Method, URL         string
    Redirect            bool
    StatusCode          int
    RequestHeader       http.Header
    ResponseHeader      http.Header
    ResponseHeaderOrder []string
    ResponseBody        []byte      // 前 MaxBody 字节
    BodyTruncated       bool
    BodyBytes           int64       // 实际读取的完整正文字节数（经分块与压缩解码）
    BodySHA256          string      // 实际读取的完整正文的摘要
    Certificates        []*x509.Certificate
    Latency             time.Duration
    Cached              bool        // 规则复用了本次扫描已有的响应
    Err                 error
}

type ExchangeLimits struct{ MaxBody, MaxHeader, MaxExchanges int } // 零值取 64 KiB / 64 KiB / 10000
```

回调在发出请求的协程中串行执行，应尽快返回；记录中的切片与映射只读，多条记录可能共用同一份数据，需要保留时自行复制。并发的多次扫描各自回调，互不串扰。

### RuleDebug

```go
type RuleDebug struct {
    Match      *FingerMatch   // 未命中时为 nil
    SubRules   []SubRuleDebug
    Evaluation RuleEvaluation
}

type SubRuleDebug struct {
    Key, Expression string
    Result          *bool // nil：请求失败、表达式出错或扫描取消
    Exchanges       []Exchange
    Evidence        []MatchEvidence
    Outputs         map[string]string
    Failure         *EvaluationFailure
}
```

入口跳转链上有多页时，`SubRules` 描述决定结果的那次评估：命中的那一页，未命中时为最后一页。调试总是采集证据，结果不交给 Writer。

### RulePolicy / ValidateRule

```go
type RulePolicy struct {
    AllowTypes   []string // 为空时允许 http、tcp、udp
    AllowRaw     bool
    AllowReverse bool     // newReverse()、newJNDI()、wait、jndi
    AllowSleep   bool
    MaxRules     int      // 0 表示不限制
    MaxSubRules  int      // 0 表示不限制
}

type ValidateOptions struct {
    Strict bool
    Policy RulePolicy
}

type Diagnostic struct {
    Code, Field, Message, Severity string // Severity: error / warning
    Line, Column                   int
}
```

`RulePolicy` 的零值表示不限制；任一字段非零时策略生效，未允许的能力一律拒绝。只允许 HTTP 写成 `RulePolicy{AllowTypes: []string{"http"}}`；允许全部类型但禁止 Raw、反连与 sleep 写成 `RulePolicy{AllowTypes: []string{"http", "tcp", "udp"}}`。加载与 `LoadFingerOptions` 重新加载时检查，内置规则库同样受检查。

`ValidateRule` 不发请求。非严格模式下存在 `error` 当且仅当使用同样 `Policy` 的 `NewEngine` 拒绝加载这条规则（YAML 无法解析、不支持的请求类型、违反规则策略）；其余问题为 `warning`。严格模式把未知键（`info.metadata` 内部除外）、缺少 `id` / `info.name` / 子规则 / 总表达式、规则标识不合规、缺少或不合规的产品声明、TCP/UDP 规则缺少服务声明、表达式无法编译也报告为 `error`。`Code` 取值：`yaml`、`unknown-key`、`missing-id`、`invalid-id`、`missing-name`、`missing-product`、`invalid-product`、`missing-services`、`invalid-service`、`missing-rules`、`missing-expression`、`expression-compile`、`policy-type`、`policy-raw`、`policy-reverse`、`policy-sleep`、`policy-sub-rules`。`Field` 是字段路径，列表项用序号表示，如 `info.product.tags.1`、`info.services.0.ports`。规则集级的检查（规则数上限、同一产品声明一致）不适用于单条规则。

### TechStack

```go
type TechStack struct {
    WebServers           []string
    ReverseProxies       []string
    JavaScriptFrameworks []string
    JavaScriptLibraries  []string
    WebFrameworks        []string
    StaticSiteGenerator  []string
    ProgrammingLanguages []string
    Caching              []string
    Security             []string
    HostingPanels        []string
    CMS                  []string // 内容管理系统（WordPress、Drupal 等）
    Databases            []string // 数据库
    Ecommerce            []string // 电商平台
    CDN                  []string // 内容分发网络
    Analytics            []string // 统计分析
    OperatingSystems     []string // 操作系统
    Other                []string // 其余未归入命名分类的识别结果，不丢弃
}
```

命名字段覆盖高价值分类；上游其余分类（Live chat、CRM、Widgets 等）归入 `Other`，每个切片去重并排序，同一输入输出稳定。

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
通过 `WithOutputFile` / `WithWriter` 注入；Engine 在每个目标
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

### 5.6 发包速率限制

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithGlobalRatePerMinute(6000), // 整个引擎每分钟最多 6000 个请求
    sdk.WithRateLimit(20, 20),         // 单台主机每秒最多 20 个请求
)
```

两种限制默认都关闭，可以单独使用，也可以同时使用：每个请求先等待总速率的名额，再等待目标主机的名额。

- **总速率**（`WithGlobalRateLimit` / `WithGlobalRatePerMinute`）约束引擎发出的全部请求，不随并发目标数放大。按分钟设置时请求匀速发出（6000 次/分钟即每 10 毫秒一个）；按秒设置时 `burst` 决定允许的瞬时突发，传 1 为严格匀速。
- **每主机速率**（`WithRateLimit`）按主机名或 IP 计，不区分端口：同一台主机上的 80、443、8080 共用一个令牌桶，限制的是这台主机承受的总速率。
- 同一主机上各端口是互不相干的服务时，加上 `WithRateLimitPerPort(true)`，每个端口各有一个令牌桶；URL 未写端口时按协议取 80 或 443。
- 计入的请求包括入口的每一跳、规则请求、TCP/UDP 规则、Raw 请求和图标请求。
- 内置规则库几乎都匹配入口页，每个目标只有几个请求；自定义规则库包含很多不同路径时，建议设置每主机速率。

### 5.7 内存监控

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithMemoryMonitor(true),
    sdk.WithMemoryThresholds(2<<30, 4<<30), // 2GB / 4GB
    sdk.WithProactiveGC(false),             // 仅告警，不触发 STW
)
```

监控结合 `runtime/metrics` 和 `runtime.ReadMemStats` 读取堆、GC 和调度延迟，内存压力高时自动降低规则并发，压力缓解后逐步恢复。数据属于整个 Go 进程，包括其他 Engine 和共享缓存，并非单个 Engine 的独占内存；阈值是调节并发的依据，不是 RSS 硬上限。

### 5.8 输出到文件 / Socket / 自定义 Writer

SDK 自带实例化 `Writer` 抽象，每个 Engine 管理自己的写入器。调用方若为不同 Engine 传入同一个自定义 Writer、Logger，或相同输出文件与 Socket 路径，外部资源会被共享，需要由调用方管理其并发和生命周期。

```go
sockWriter, _ := sdk.NewSockWriter("/tmp/gxx.sock")
engine, _ := sdk.NewEngine(ctx,
    // 写入 JSON Lines（每行一条结果）
    sdk.WithOutputFile("results.json", sdk.FormatJSON),
    // 同时广播到 Unix socket
    sdk.WithWriter(sockWriter),
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

// 规则来自内存文件系统（如从数据库读出的规则）
rules := fstest.MapFS{"demo.yaml": {Data: content}}
engine, err := sdk.NewEngine(ctx, sdk.WithRuleFS(rules, "."))

// 入库前校验
for _, d := range sdk.ValidateRule(content, sdk.ValidateOptions{Strict: true}) {
    fmt.Printf("%s 第 %d 行 %s：%s\n", d.Severity, d.Line, d.Field, d.Message)
}
```

### 5.10 网络策略、求值报告与交换观察

```go
engine, _ := sdk.NewEngine(ctx, sdk.WithNetworkPolicy(sdk.NetworkPolicy{
    CheckTarget: func(ctx context.Context, r sdk.TargetRequest) error {
        if r.Host == "169.254.169.254" {
            return errors.New("拒绝访问元数据地址")
        }
        return nil
    },
}))

var report sdk.EvaluationReport
result, err := engine.ScanWith(ctx, target,
    sdk.ScanEvaluationReport(&report),
    sdk.ScanObserver(func(ex sdk.Exchange) {
        log.Printf("#%d %s %s %d %s", ex.Sequence, ex.Kind, ex.URL, ex.StatusCode, ex.BodySHA256)
    }, sdk.ExchangeLimits{MaxBody: 4096}),
)
if !report.Complete {
    // 有规则没有完整求值：未命中不一定可信
}

debug, err := engine.DebugRule(ctx, target, "wordpress")
for _, sub := range debug.SubRules {
    fmt.Println(sub.Key, sub.Result, len(sub.Exchanges), sub.Failure)
}
```

---

## 六、并发安全 / 生命周期

### 6.1 安全保证

| 操作 | 并发安全 | 说明 |
|------|---------|------|
| `NewEngine` | ✅ | 每次调用返回独立实例 |
| `(*Engine).Scan` / `ScanWith` / `ScanBatch` / `ScanCallback` / `ScanIterator` / `DebugRule` | ✅ | 同一 Engine 多 goroutine 调用安全 |
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

## 七、示例项目

完整示例位于 `example/` 目录：

| 目录 | 演示内容 |
|------|---------|
| `example/basic_scan/` | 基本单目标扫描 + functional options |
| `example/api_scan_baidu/` | API 调用 + sentinel error 处理 |
| `example/file_target_scan/` | 从文件批量扫描 + ScanCallback 流式回调 |
| `example/proxy_scan/` | 通过代理扫描 + 每主机限速 |
| `example/wappalyzer_scan/` | 多目标技术栈识别（同 Engine 复用） |
| `example/output_writer/` | `WithOutputFile` JSON Lines + 自定义 Writer（计数 / Kafka / Webhook） |

---

## 八、注意事项

- 所有扫描 API 第一个参数是 `context.Context`，支持超时与取消（透传给底层 HTTP 客户端 + per-host 限流 Wait）
- SDK 内部已实现请求缓存、对象池、并发控制、限流、监控，调用方无需额外管理
- 长期复用 Engine；大批量任务使用 `ScanCallback` 及时消费结果，输入也需要流式读取时使用 `ScanIterator`，避免把所有目标和响应保留在切片中
- 按 CPU、目标延迟和响应大小配置并发，资源受限时可从 URL 并发 2、规则并发 32、缓存 16 MiB 开始测量；这些设置不裁剪规则，但可能增加排队时间
- 请求缓存使用异步淘汰，字节预算是估算容量；不同扫描的缓存作用域互相隔离，并共享实例容量预算。同次扫描内可缓存的相同普通 GET 合并执行，清理只影响所属扫描
- 静态规则快照持有连续的不可变执行清单；仅依赖已缓存首页且没有动态声明、循环或等待的指纹可按最多 8 条合并调度，每条独立评估、计数和处理异常。其他指纹按单条任务执行，规则并发与在途指纹预算保持不变；求值状态归还时清除响应和其他扫描状态，循环、I/O 和等待函数保留取消约束
- 引擎内部构造的响应按只读所有权共享；公共缓存写入复制调用方的完整消息，超过字节预算时跳过缓存，不生成被裁剪的缓存响应。实例请求头在构造时复制，规则覆盖头只作用于对应请求
- 标题解析直接消费只读正文的字节视图；标题与 ICP 备案号独立持有返回字符串，长期保留结果不会通过这些字段引用整页 HTML 或脚本。无候选的合法 UTF-8 正文无需为备案号解析复制整页；结果数量增长仍会增加内存
- favicon 哈希使用 1,824 字节原始块和 2,465 字节编码块读取到 EOF，不构造完整图片或 Base64 副本；入口页支持非根路径、跳转、多个候选与内联图片。成功哈希归当前实例持有，按请求头和 Cookie 会话隔离，候选回退共用时间预算；同一组图片字节的哈希编码约定不变。元数据识别范围与限制见 [网站元数据识别](../docs/网站元数据识别.md)
- 未知长度响应使用 32 KiB 暂存块，暂存池最多保留 1 MiB，最终正文使用独立数组；已知长度响应采用有界容量提示，两条路径保持相同的正文上限和读取错误语义
- 页面正文上限默认 512 KiB（`WithBodyLimit` 设置）；图标不受该资源大小限制，使用固定块读取到 EOF。内联图标声明仍需包含在已读取的页面正文中

- 大响应的重复字节包含查询可使用按需构造的 8 KiB 片段位图。候选仍调用原始包含函数，位图饱和、响应太小或复用次数不足时使用直接匹配；相关响应数据共用单次扫描 8 MiB 的估算预算
- 技术栈识别按响应字段建立索引，正文通过必要字面量索引筛选候选；全部 HTTP 规则保持可用，候选由上游解析器判定。编译正则按 512 条工作集共享缓存，淘汰后可重新编译，不裁剪规则；覆盖大量不同模式的负载可能增加编译开销
- 响应正文按声明的字符集解码为 UTF-8：优先 Content-Type 头，其次正文前部的 `<meta charset>`，支持 UTF-8/GBK/GB18030/Big5/Shift_JIS/ISO-8859-1 等；无任何声明时合法 UTF-8 原样保留，否则按 GB18030 兜底（面向省略或错误标注字符集的中文站点）。CEL 规则中的 `response.body` / 标题 / ICP 均基于解码后的 UTF-8 字节
- 一个目标是一个资产（协议 + 主机 + 端口）。入口与规则请求的 30x 默认跟随，可以指向其他主机；页面里识别出的刷新与脚本跳转只在资产内跟随，指向其他资产时不访问，地址写入 `RedirectTo`。离开扫描目标后只带通用请求头，自定义请求头不会发往其他主机。跳转链上的每一页都参与根路径规则匹配。网络策略的 `Redirect` 可以阻止跟随任意一跳。完整规则见 [资产与跳转](../docs/资产与跳转.md)
- 每次扫描使用独立的 Cookie 会话，入口、规则与图标请求共用，扫描结束即释放。同一 Engine 对同一目标的多次扫描互不影响，引擎不随目标数量累积 Cookie
- 自定义 `Writer.Write` 收到的 `*TargetResult` 与调用方拿到的是同一指针，必须视为只读、不得在返回后异步持有；需异步使用时自行深拷贝。内置 FileWriter 入队前已深拷贝，SockWriter 在调用内同步序列化
- CLI 输出完成后只保留汇总计数，不保留全量结果；目标去重集合仍随唯一目标数增长
- 不要用每目标强制 GC 控制内存；RSS 还包括 Go 运行时保留页、线程栈和原生组件，通常高于存活堆
- 所有对外类型均在 `sdk` 包内定义或以类型别名导出（如 `NetworkPolicy`、`Exchange`），**不需要**导入 `gxx/types` 或 `gxx/pkg/*` 等内部包

读取策略、实例归属和验证记录见[资源读取与实例隔离](../docs/资源读取与实例隔离.md)。
