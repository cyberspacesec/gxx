# GXX 指纹识别工具使用示例（v3.0 Engine API）

> v3.0 (2026-05-22) 全实例化重构：所有示例统一使用 `*sdk.Engine` 实例化 API，  
> 旧的 `gxx.FingerScan / gxx.InitFingerRules / gxx.GetBaseInfo` 等包级函数已移除。

---

## 示例目录

### 1. [基础扫描](basic_scan/)

最基本的扫描示例，用 `(*Engine).Scan` 对单 / 多个目标做完整指纹识别。

**演示要点**：
- `sdk.NewEngine` + functional options 构造
- `defer engine.Close()` 资源管理
- 提取 ICP 备案号、证书、技术栈

### 2. [代理扫描](proxy_scan/)

通过 HTTP/SOCKS5 代理扫描 + per-host 限流。

**演示要点**：
- `sdk.WithProxy("http://...")` / `socks5://`
- `sdk.WithRateLimit(qps, burst)` per-host 令牌桶
- `debug.HostRateLimiterStatsOf(engine)` 限流器状态查询

### 3. [文件批量扫描](file_target_scan/)

从文件批量读取目标 + `(*Engine).ScanCallback` 流式回调。

**演示要点**：
- 不需要等所有目标完成，边扫边出结果
- `sdk.WithURLConcurrency(20)` 控制并发，无需自己写 goroutine pool
- 回调返回 `false` 主动取消整批

### 4. [API 集成扫描](api_scan_baidu/)

`(*Engine).GetBaseInfo` + `(*Engine).Scan` 组合使用 + sentinel error 处理。

**演示要点**：
- `errors.Is(err, sdk.ErrEngineClosed)` 判断错误类型
- 同一 Engine 复用执行多种 API

### 5. [Wappalyzer 技术栈识别](wappalyzer_scan/)

仅执行技术栈识别（不跑指纹匹配）。

**演示要点**：
- 同一 `*Engine` 跨多目标复用
- `GetBaseInfo` vs `WappalyzerScan` 两种取技术栈方式

### 6. [Writer 输出](output_writer/)

通过 v3 新增的 `Writer` 抽象把结果写入文件 / 注入自定义收集器。

**演示要点**：
- `sdk.WithOutputFile(path, sdk.FormatJSON)` 内置 JSON Lines 文件写入
- `sdk.WithWriter(...)` 注入自定义 Writer（计数 / Kafka / Webhook 等）
- Writer 与 `ScanCallback` 同时启用，Engine.Close 自动 flush

---

## 运行示例

```bash
cd example/<示例目录>
go run main.go
```

> 示例通过 `fingerYaml/loader.go`（默认构建，无 tag）向上查找 `fingerYaml/`；使用 `make build-embed` 或 `-tags embed` 时由 `fingerYaml/embed.go` 从二进制内嵌规则加载。

---

## v3.0 SDK API 速览

### 创建 Engine

```go
ctx := context.Background()
engine, err := sdk.NewEngine(ctx,
    sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "fingerYaml"}),
    sdk.WithTimeout(10*time.Second),
    sdk.WithRuleConcurrency(500),
    sdk.WithRateLimit(50, 100),
    sdk.WithMemoryMonitor(true),
)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()
```

### 扫描方法

```go
// 单目标
result, err := engine.Scan(ctx, "https://example.com")

// 仅基础信息
info, err := engine.GetBaseInfo(ctx, target)

// 仅技术栈
ts, err := engine.WappalyzerScan(ctx, target)

// 一次性批量
results, err := engine.ScanBatch(ctx, []string{"a.com", "b.com"})

// 流式回调批量（推荐）
err := engine.ScanCallback(ctx, targets, func(r *sdk.TargetResult) bool {
    fmt.Printf("✓ %s\n", r.URL)
    return true
})

// URL 规范化
url, err := engine.NormalizeURL(ctx, target)

// 运行期切换指纹库
engine.LoadFingerOptions(sdk.FingerOptions{PocYaml: "single.yaml"})
```

### 查询 / 统计

```go
engine.FingerCount()      // int
engine.PoolStats()        // PoolStats{TotalTasks, CompletedTasks, FailedTasks}
engine.CacheStats()       // map[string]any（含 hit_ratio / evictions / hits / misses）
engine.MemoryStats()      // runner.MemoryStats（含 GoSchedLatency p99）
```

---

## 主要 Functional Options

| Option | 默认值 | 说明 |
|--------|--------|------|
| `WithFingerOptions(opts FingerOptions)` | 嵌入式 | 指纹规则文件 / 目录 |
| `WithProxy(addr string)` | `""` | http / socks5 代理 |
| `WithTimeout(d time.Duration)` | 10s | 请求超时 |
| `WithURLConcurrency(n int)` | 5 | URL 并发 |
| `WithRuleConcurrency(n int)` | 200 | 规则并发 |
| `WithCacheSize(n int)` | 2048 | 请求/响应缓存条目上限 |
| `WithCacheTTL(d time.Duration)` | 10min | 缓存 TTL |
| `WithRateLimit(qps float64, burst int)` | 关闭 | per-host 限流 |
| `WithMemoryMonitor(enable bool)` | false | 启动内存监控 |
| `WithMemoryThresholds(high, critical uint64)` | 2GB / 4GB | 内存告警阈值 |
| `WithProactiveGC(enable bool)` | false | 压力时主动 GC |
| `WithDisableKeepAlives(disable bool)` | false | 禁用 HTTP Keep-Alive |
| `WithCustomHeaders(map[string]string)` | nil | 全局请求头 |
| `WithInsecureSkipVerify(skip bool)` | true | 跳过 TLS 验证 |
| `WithDebug(enable bool)` | false | 调试日志（无需 `logger.InitLogger`） |

---

## Sentinel Errors

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

```go
result, err := engine.Scan(ctx, target)
if errors.Is(err, sdk.ErrEngineClosed) {
    // 处理引擎已关闭
}
```

---

## 调试 / 运维 API（`gxx/sdk/debug`）

```go
import "github.com/cyberspacesec/gxx/sdk/debug"

stats := debug.MemoryStatsOf(engine)            // 实时内存快照
debug.ForceGC()                                 // 强制 GC（仅诊断）
rl := debug.HostRateLimiterStatsOf(engine)      // 限流器状态
```

---

## 完整文档

- SDK 详细文档：[sdk/sdk.md](../sdk/sdk.md)
- 开发者文档：[develop.md](../develop.md)
- 优化方案：[optimization-plan.md](../optimization-plan.md)
