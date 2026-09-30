# GXX 开发者文档

> 基于 YAML 规则 + CEL 表达式的高性能指纹识别引擎，源码阅读与开发参考文档。

---

## 一、项目定位

GXX 是一款用 Go 编写的网络资产指纹识别引擎，核心目标是「大规模、高并发、低内存」地对 HTTP/HTTPS/TCP/UDP 目标进行存活探测与组件指纹匹配。

**核心能力**：

- **YAML 规则引擎**：以 YAML 为规则载体、以 Google CEL（Common Expression Language）为匹配语言，规则编写简洁、表达力强
- **两级并发调度**：URL 级 + 规则级独立线程池，ants 协程池底层支撑，支持 200~5000 并发规则
- **多协议支持**：HTTP/HTTPS、TCP、UDP、Raw HTTP（基于 projectdiscovery/rawhttp）
- **多维度信息提取**：标题、Server 头、证书、ICP 备案号、Favicon Hash、Wappalyzer 技术栈
- **多格式输出**：TXT / CSV / JSON 三种文件格式 + Unix Domain Socket 实时流式输出
- **双形态交付**：CLI 二进制（`cmd/main.go`）+ Go SDK 库（`sdk/`），SDK 所有对外类型自包含、支持 `context.Context`
- **指纹库可嵌入**：通过 `go:embed` 将 `fingerYaml/` 下 2000+ 条规则编入二进制，单文件部署

---

## 二、技术栈

| 层级 | 关键依赖 | 用途 |
|------|---------|------|
| 语言 | Go 1.25 | 主体语言 |
| 表达式引擎 | `github.com/google/cel-go` | CEL 规则编译与求值 |
| 并发池 | `github.com/panjf2000/ants/v2` | URL/规则两级协程池 |
| HTTP 客户端 | `github.com/zan8in/retryablehttp` | 带重试的 HTTP 客户端 |
| Raw HTTP | `github.com/projectdiscovery/rawhttp` | 原始 HTTP 报文请求 |
| 技术识别 | `github.com/projectdiscovery/wappalyzergo` | Wappalyzer 技术栈匹配 |
| 命令行 | `github.com/projectdiscovery/goflags` | 命令行参数解析 |
| 代理 | `github.com/chainreactors/proxyclient` | HTTP/SOCKS5 代理拨号 |
| 日志 | `github.com/sirupsen/logrus` + `lumberjack` | 终端 + 滚动文件日志 |
| 进度条 | `github.com/schollz/progressbar/v3` | 终端进度展示 |
| 正则 | `github.com/dlclark/regexp2` | 兼容 .NET 风格的正则 |
| 哈希 | `github.com/spaolacci/murmur3` | Favicon Mmh3 计算 |
| 协议 | `google.golang.org/protobuf` | proto.Request/Response 序列化 |
| 编码 | `github.com/axgle/mahonia` | GB18030 → UTF-8 |
| YAML | `gopkg.in/yaml.v2` | 指纹规则解析 |

---

## 三、目录结构（按调用方向）

```
gxx/
├── cmd/                              # ① 入口层
│   ├── main.go                       # 程序入口，负责 Banner / Options / Logger / Output 初始化
│   └── cli/
│       ├── banner.go                 # 启动 Banner，版本/作者/构建时间通过 ldflags 注入
│       ├── cmd.go                    # Run() 包装：启动监控 → 创建 Runner → 执行
│       └── options.go                # CLI 参数定义与校验（基于 goflags）
│
├── sdk/                              # ② SDK 对外层（v3 全实例化 API）
│   ├── sdk.go                        # 对外类型 + NewFingerOptions
│   ├── engine.go / options.go / errors.go
│   ├── writer.go / writer_test.go    # 实例化 Writer 抽象（File/Sock/Multi/Nop）
│   ├── sdk.md                        # SDK 使用文档
│   └── debug/
│       └── debug.go                  # MemoryStatsOf(engine) / HostRateLimiterStatsOf(engine) / ForceGC
│
├── pkg/                              # ③ 引擎核心
│   ├── runner/
│   │   ├── runner.go / runner_cli.go # *Runner 实例 + CLI 批量扫描
│   │   ├── scan.go                   # ScanTarget / 指纹匹配 / 结果收集
│   │   ├── fingerprint.go / cache.go / pool.go / monitor.go
│   │   ├── internal_pool.go          # sync.Pool 对象复用
│   │   └── types.go
│   │
│   ├── finger/                       # 指纹规则解析与执行
│   │   ├── yaml.go                   # Finger / Rule / RuleMap 结构 + YAML 加载（保序）
│   │   ├── runner.go                 # SendRequest：HTTP/TCP/UDP/Raw 协议分发
│   │   ├── req.go                    # formatPath/formatBody + buildProtoRequest/Response
│   │   ├── eval.go                   # IsFuzzSet（set 变量解析）+ SetVariableMap（{{var}} 替换）
│   │   ├── title.go                  # 网页标题提取（含字符集探测 / i18n JS 兜底）
│   │   ├── server.go                 # 从 Server 头提取服务器类型与版本
│   │   ├── cert.go                   # TLS 证书结构化提取
│   │   ├── icp.go                    # HTML 内 ICP 备案号提取（多重正则 + 锚文本兜底）
│   │   └── icon.go                   # Favicon URL 解析 + Mmh3 Hash 计算
│   │
│   ├── cel/                          # CEL 表达式引擎封装
│   │   ├── cel.go                    # 全局 baseEnv 单例 + Program 缓存（sync.Map）
│   │   ├── celcompile.go             # CEL 环境基础选项（类型/变量声明）
│   │   └── celprogram.go             # 自定义函数库（icontains/bcontains/base64/md5/regex...）
│   │
│   ├── network/                      # 网络请求层
│   │   ├── http.go                   # retryablehttp 客户端池化 + 重定向策略 + Transport 缓存
│   │   ├── network.go                # TCP/UDP Client 实现（含 TLS / 代理 / 重试）
│   │   ├── raw_http.go               # rawhttp 原始 HTTP 请求
│   │   ├── raw.go                    # 原始报文解析（用于 raw 规则）
│   │   └── raw_parse.go              # TCP/UDP 响应封装为 proto.Request/Response
│   │
│   └── wappalyzer/
│       └── wappalyzer.go             # Wappalyzer 全局单例 + 11 类技术分类格式化
│
├── types/                            # 公共类型
│   ├── options.go                    # CmdOptions / YamlFingerType
│   ├── server.go                     # ServerInfo
│   └── cert.go                       # CertInfo / CertName
│
├── utils/                            # 基础设施
│   ├── common/                       # 通用工具：UA 池、编码、哈希、URL 处理、地址解析
│   ├── config/                       # 反连平台配置（Ceye/JNDI）
│   ├── logger/                       # 双 logger 架构（终端彩色 + 文件 plain），延迟格式化
│   ├── output/                       # 多格式输出：file.go / sock.go / console.go
│   └── proto/                        # http.proto + 编译后的 http.pb.go（CEL 的 request/response 模型）
│
├── fingerYaml/                       # 内置指纹库（go:embed 嵌入）
│   ├── embed.go                      # -tags embed：go:embed 编入二进制
│   ├── loader.go                     # 默认构建（无 tag）：从磁盘 fingerYaml/ 加载
│   ├── fingerprints/                 # 指纹规则集 1
│   ├── fingers/                      # 指纹规则集 2
│   ├── fofa/                         # FOFA 风格规则
│   └── jiajiu/                       # 主指纹库（2300+ YAML 文件）
│
└── example/                          # 6 个 SDK 调用示例
    ├── basic_scan/                   # 基础单目标
    ├── api_scan_baidu/               # API 集成
    ├── file_target_scan/             # 批量文件
    ├── proxy_scan/                   # 代理扫描
    ├── wappalyzer_scan/              # 技术栈识别
    └── output_writer/                # Writer 输出（文件 + 自定义 Writer）
```

---

## 四、核心数据流

### 4.1 端到端调用链

```
main.go
  └─ cli.Run(options)
       └─ runner.NewRunner(scanCfg, pocOptions)   // 实例化 FingerStore/RulePool/Cache/Monitor/HTTPClient
            └─ (*Runner).Run(ctx, options)
                 ├─ LoadTargets / output.InitOutput
                 └─ executeScan(ctx, targets, options)
                      └─ URL 工作池（默认 5 并发）
                           └─ (*Runner).ScanTarget(ctx, target)
                                ├─ limiter.Wait（可选 per-host）
                                ├─ getBaseInfo(ctx) → HTTPClient.CheckProtocol + SendRequestHttp
                                ├─ warmUpRequestCache()
                                └─ executeFingerprintMatching(ctx, ...)
                                     └─ RulePool.Submit(RuleTask{Ctx: ctx, ...})
                                          └─ processRuleTask → evaluateFingerprint(ctx, ...)
                                               ├─ CacheManager.ShouldUseCache
                                               ├─ finger.SendRequest(ctx, httpClient, ...)  // 继承 Scan 取消
                                               └─ CEL Evaluate

sdk.NewEngine → *runner.Runner（字段一一对应，无全局共享状态）
              → buildWriter(cfg)：装配 FileWriter / SockWriter / 自定义 Writer，合并为 MultiWriter
(*Engine).Scan / ScanCallback / ScanBatch
              → e.runner.ScanTarget → convertTargetResult
              → e.dispatchWriter(ctx, out)  // 写入失败仅 stderr 提示，不影响业务返回
(*Engine).Close → 先 flush Writer → 再释放 pool/cache/monitor/httpClient，恢复 debug 日志级别
```

### 4.2 执行阶段图

```
目标输入 ─┬─> ① 存活探测 ─┬─> 标题
          │   (GET /)      ├─> 证书
          │                ├─> Server
          │                ├─> ICP
          │                └─> Wappalyzer
          │
          ├─> ② 缓存预热（GET / 的请求/响应写入 Runner 实例缓存）
          │
          ├─> ③ 规则匹配（2300+ 规则并发执行）
          │     ├─> 缓存命中 → 直接 CEL 求值
          │     └─> 缓存未命中 → 发新包 → CEL 求值
          │
          └─> ④ 结果输出（控制台 + 文件 + Socket）
```

---

## 五、核心模块详解

### 5.1 `cmd/` — 入口与命令行

**职责**：解析参数、初始化日志/输出、调用 Runner。

- `main.go` 的 36~80 行：根据 `--debug` 决定日志级别（INFO=1 / DEBUG=4），根据扩展名或 `--json` 决定输出格式（txt/csv/json）
- `cli/options.go` 的 `verifyOptions`：对 target/output/threads/timeout 做防御性校验，无效值回退默认
- `cli/cmd.go` 的 `Run`：`NewRunner` + `defer Close` + `Run(ctx, options)`

**关键参数**：

| 参数 | 默认值 | 上限 | 说明 |
|------|--------|------|------|
| `-t / --threads` | 5 | ∞ | URL 级并发 |
| `-rt / --rulethreads` | 200 | 5000 | 规则级并发（Runner 实例 RulePool） |
| `--timeout` | 3 秒 | ∞ | 单次请求超时 |
| `--json` | false | - | JSON 格式输出（高于扩展名判断） |

### 5.2 `pkg/runner/` — 扫描调度器（核心）

**最关键的目录**，包含两套并发模型、缓存系统、内存监控。

#### 5.2.1 两级线程池

- **URL 池**（`executeScan`）：默认 5 协程，每协程处理一个目标的完整流程
- **规则池**（`*RulePool` 实例）：默认 200 总 worker（MultiPool 分 shard），处理带 `Ctx` 的 RuleTask
- **回压控制**：每个 URL 协程提交规则任务时通过 `limiter chan struct{}`（容量 = 规则线程数 × 2）做信号量，防止内存爆炸

#### 5.2.2 缓存机制（`cache.go`）

- **底层**：`otter/v2` W-TinyLFU + `ExpiryWriting` TTL；`OnAtomicDeletion` 同步清理二级索引
- **结构**：`CacheManager` = otter 主缓存 + targetIndex（URL → 缓存 key 集合）+ keyIndex（缓存 key → URL）
- **键生成**：`MD5(target + ":" + method + ":" + followRedirects)`
- **容量 / TTL**：默认最多 2048 条、TTL 10 分钟（由 `ScanConfig.CacheMaxSize` / `CacheTTL` 配置，支持亚秒级 `time.Duration`）
- **缓存条件**：HTTP/HTTPS + GET/POST + 空 headers + 空 body
- **写入限流**：缓存的 Body/Raw/RawHeader 最大 1 MB（`maxCacheBodySize`），防止大响应撑爆内存

#### 5.2.3 对象池（`internal_pool.go`）

| 对象池 | 作用 |
|--------|------|
| `ruleTaskPool` | 复用 RuleTask 结构 |
| `varMapPool` | 复用 `map[string]any`（每条规则一份变量表） |
| `fingerMatchPool` | 复用 FingerMatch |

每次 Get 时手动清零字段，Put 时再次清零，确保不泄漏旧引用。

#### 5.2.4 指纹快照缓存（`fingerprint.go`）

- 使用 `fingerVersion` 版本号 + `cachedSnapshot` 缓存：扫描期间指纹列表不变，无需每次都 `make + copy`
- `FingerStore.Load` 改写指纹时递增 `version`，使快照失效
- `FingerStore.Snapshot` 在版本未变时直接返回惰性缓存切片

#### 5.2.5 内存监控（`monitor.go`）

- 15 秒采样一次（早期为 5 秒，已调优降频）
- 高阈值 2 GB → 触发 `runtime.GC()`
- 临界阈值 4 GB → 触发 `debug.FreeOSMemory()` 归还 OS
- 内存使用率 > 85% 同样触发 GC
- Goroutine 数量超过 15000 时输出告警

### 5.3 `pkg/finger/` — 指纹规则模型

#### 5.3.1 规则结构（`yaml.go`）

```go
Finger {
  Id         string         // 规则 ID
  Transport  string         // http/tcp/udp
  Set        yaml.MapSlice  // 全局变量（保序）
  Payloads   Payloads       // 多 payload 探测
  Rules      []RuleMap      // 子规则集合（保序，靠 order 字段）
  Expression string         // 最终判定表达式，如 "r0() && (r1() || r2())"
  Info       Info           // 元信息（name/author/severity/tags/cvss...）
}
```

**保序解析**：`RuleMapSlice.UnmarshalYAML` 在当前调用内读取 `yaml.MapSlice` 的顺序和类型化规则，保证 `r0/r1/r2` 按源文件顺序加载；重复名称采用最后一次定义及其位置。解析不依赖包级计数器或锁。

#### 5.3.2 协议分发（`runner.go` 的 `SendRequest`）

根据 `rule.Request.Type` 路由到不同实现：

| Type | 实现 | 关键点 |
|------|------|--------|
| `http`（默认） | `(*network.HTTPClient).SendRequestHttp` | 实例客户端，支持 307/308 重定向 |
| `tcp` | `network.NewClientContext` | 可选 TLS，支持 hex 数据及取消 |
| `udp` | `network.NewClientContext` | UDP 客户端，遵循超时和取消 |
| `raw` (HTTP) | `network.SendRawRequest` | 原始报文编解码，遵循实例代理、TLS、限流和取消 |

#### 5.3.3 信息提取子模块

- **`title.go`**：3 层兜底（HTML `<title>` → JS `document.title` → i18n JS 文件中的 `top.login.title`），自动处理 GBK/UTF-8 字符集
- **`icp.go`**：扫描可见文本中的短候选，处理实体、行内标签、全角和 GB18030；排除脚本、注释、模板与属性样例，备案官网锚文本优先
- **`icon_extract.go` / `icon.go` / `icon_stream.go`**：依次验证声明图标、根路径和图片线索，按固定块计算完整资源的 Mmh3 Hash；资源缓存属于当前 HTTP 客户端。入口页和根路径 GET HTML 提取图标，其他规则路径不重复提取
- **`cert.go`**：提取 Subject/Issuer 全字段、NotBefore/NotAfter、SAN（DNS/IP/URI/Email）、CRL/OCSP/CA 链 URL、SPKI 的 SHA1 公钥指纹

### 5.4 `pkg/cel/` — 表达式引擎（高性能关键）

#### 5.4.1 双层环境模型

```
全局唯一 baseEnv (sync.Once 初始化)
        │
        │ Extend(动态选项)
        ▼
每个规则的 CustomLib.env (按需派生)
```

- **`baseEnv`**：包含所有固定类型声明（`request`/`response` 等 proto 类型）和全部自定义函数（icontains/bcontains/base64/md5/regex...）
- **`CustomLib`**：保存动态添加的 `cel.Variable(name, type)`（如规则中 `set` 定义的变量），按需调用 `baseEnv.Extend()` 派生子环境

这一改造解决了「每条规则都 `cel.NewEnv()`」带来的重量级初始化开销。

#### 5.4.2 Program 缓存（`cel.go` L93~97）

CEL 编译结果 `cel.Program` 是 stateless / thread-safe / cacheable 的，所以：

- 用 `sync.Map`（key = 表达式字符串，value = `cel.Program`）缓存基础环境编译的 Program
- 相同表达式（如 `response.status == 200`）零重复编译

#### 5.4.3 自定义函数库（`celprogram.go`）

| 类别 | 函数 |
|------|------|
| 字符串 | `icontains`、`substr`、`replaceAll`、`printable`、`toUintString` |
| 字节流 | `bcontains`、`ibcontains`、`bstartsWith`、`bmatches`、`submatch`、`bsubmatch` |
| 编码 | `md5`、`base64`、`base64Decode`、`urlencode`、`urldecode`、`hexdecode`、`faviconHash` |
| 随机 | `randomInt`、`randomLowercase` |
| 反连 | `wait`（Ceye）、`jndi`（JNDI Ldap） |
| 时间 | `year`、`shortyear`、`month`、`day`、`timestamp_second`、`sleep` |

### 5.5 `pkg/network/` — 网络层

#### 5.5.1 客户端复用（`http.go`）

- **Transport 缓存**（`transportCache sync.Map`）：按 `proxyURL` 缓存 `*http.Transport`，每 5 分钟关闭空闲连接，超过 100 条时整体重置
- **Client 缓存**（`clientCache sync.Map`）：按 `(proxy, timeout, followRedirects)` 三元组缓存 `*retryablehttp.Client`，避免每次请求新建
- **CookieJar**：自动按域名路径管理 Cookie（基于 `golang.org/x/net/publicsuffix`）
- **LoggingTransport**：DEBUG 模式下转储请求/响应头到日志（不含 body）

#### 5.5.2 协议探测（`CheckProtocol`）

- 签名：`CheckProtocol(ctx, host, proxy, timeout)`，遵守调用方 ctx 与 `ScanConfig.Timeout` / `WithTimeout`
- 优先 HTTPS（基于「绝大多数现代站点支持 https」假设）→ 失败回退 HTTP
- 80 端口强制 HTTP，443 端口强制 HTTPS，其他端口先探 HTTPS

#### 5.5.3 重定向策略（`createRedirectPolicy`）

- 最多 5 次重定向
- 关键处理：307/308 重定向必须保留原始 Method 和 Body，作者实现了完整的 `GetBody` 注入逻辑，保证 POST 请求重定向时 Body 可重读

### 5.6 `pkg/wappalyzer/` — 技术栈识别

- **单例**：通过 `sync.Once` 全局只创建一个 `wappalyzer.Wappalyze` 实例（启动时一次性加载所有指纹库）
- **分类映射**：将 wappalyzergo 的原始分类映射到 11 个自定义维度（WebServers/JavaScriptFrameworks/Caching/Security 等）

### 5.7 `utils/output/` — CLI 多格式输出

| 格式 | 实现 | 特性 |
|------|------|------|
| TXT | `file.go` 字符串拼接 | 含分隔线和换行 |
| CSV | `encoding/csv` + UTF-8 BOM | Excel 友好 |
| JSON | `encoding/json.MarshalIndent` | 每行一个 JSON 对象 |
| Socket | Unix Domain Socket + JSON | 实时推送，支持多客户端连接 |

**线程安全**：所有写操作通过 `mu sync.Mutex` 串行化；Socket 连接集合通过 `sockConnMutex` 保护。
异步写入器（`async_writer.go`）把格式化 + 落盘从 URL 工作池剥离，URL worker 仅做 O(1) 入队，
队列满时调用方回退同步写以保证不丢数据。

> CLI 入口（`cmd/main.go` → `runner.Run`）走该包；SDK 调用方应改用 `sdk.Writer`
> 抽象（见 5.9），后者每个 Engine 持有独立实例，与 utils/output 包级状态完全解耦。

### 5.8 `utils/logger/` — 双 Logger 架构

- **terminalLogger**：彩色输出到 stdout，含 ANSI 转义
- **fileLogger**：通过 `PlainFormatter` 用正则剥离 ANSI 后写入 lumberjack（按日切割、最多 5 份、单文件 50 MB、保留 10 天、自动 gzip）
- **延迟格式化优化**：所有日志方法先判断级别，未达到直接 return，避免无意义的 `fmt.Sprintf`（DEBUG 模式下 logger 已优化为零字符串分配）

### 5.9 `sdk/` — 对外 API 设计

**设计原则**：

1. 所有对外类型在 `sdk.go` 内重新定义（如 `TargetResult`/`FingerInfo`/`TechStack`），调用方零内部包依赖
2. 所有扫描 API 首参数为 `context.Context`，支持超时与取消
3. 通过 `convertTargetResult` / `convertServerInfo` / `convertTechStack` / `convertCerts` 在内部类型与 SDK 类型之间转换，保持内外解耦
4. `NewEngine` 在 `PocFile` / `PocYaml` 为空时自动加载嵌入式指纹库
5. `sdk/debug` 子包独立暴露运维接口，与业务 API 分离
6. **`sdk/writer.go`** 提供实例化 `Writer` 抽象：每个 Engine 持有独立 Writer，
   不依赖任何包级全局状态。内置 `NopWriter` / `FileWriter`（txt/csv/json，自带 1024 容量
   异步队列）/ `SockWriter`（Unix domain socket 广播）/ `MultiWriter`；
   通过 `WithOutputFile` / `WithSockOutputFile` / `WithWriter` 注入，
   Engine 在 `Scan` / `ScanCallback` 完成单目标后自动派发到 Writer，
   写入失败仅 stderr 提示不影响业务返回值，`Close` 时先 flush Writer 再释放 Runner。

---

## 六、性能优化清单

| 优化项 | 实现位置 | 收益 |
|--------|---------|------|
| CEL 基础环境单例 + `Extend()` 派生 | `pkg/cel/cel.go` | 消除每条规则 `cel.NewEnv()` 的重量级开销 |
| CEL Program 缓存（sync.Map） | `pkg/cel/cel.go` L93 | 相同表达式零重复编译 |
| 延迟格式化日志 | `utils/logger/logger.go` L227 | 非 Debug 模式下零字符串分配 |
| `SetVariableMap` 跳过 proto 对象 | `pkg/finger/eval.go` L66 | 消除 64% protobuf 文本序列化开销（9.3GB → 0） |
| HTTP 客户端池化（按配置 key） | `pkg/network/http.go` L305 | 相同配置复用客户端实例 |
| Transport 缓存（按代理 URL） | `pkg/network/http.go` L252 | 复用 TCP 连接池 |
| Wappalyzer 全局单例 | `pkg/wappalyzer/wappalyzer.go` L46 | 启动时加载一次，全程共享 |
| 指纹快照版本号缓存 | `pkg/runner/fingerprint.go` L25 | 扫描期间只复制一次指纹列表 |
| 内存监控降频（5s → 15s） | `pkg/runner/monitor.go` L65 | 减少 ReadMemStats 引起的 STW |
| 缓存 Body/Raw 上限 1MB | `pkg/runner/cache.go` | 防止大响应撑爆缓存 |
| 响应体读取上限 512KB | `pkg/network/http.go` L76 | `io.LimitReader` 防止超大响应 |
| 对象池（RuleTask/varMap/FingerMatch） | `pkg/runner/internal_pool.go` | 减少高频小对象分配 |
| URL 池 + 规则管道 limiter 回压 | `pkg/runner/scan.go` | 防止内存爆炸，平滑调度 |
| Favicon 按需抓取 | `pkg/finger/req.go` L99 | 仅首页 GET + HTML 时抓取，避免高并发下重复网络请求 |
| 流式读取目标文件 | `pkg/runner/runner_cli.go` LoadTargets | 1 MB 行缓存，去重边读边做 |

**实测数据**（README 提供）：16 目标 × 2348 规则 → 总分配 11.8 GB / 峰值堆 539 MB / 最终残留 147 MB / GC CPU 3% / 耗时 20s，race detector 验证零 goroutine 泄漏。

---

## 七、指纹规则语法（CEL 表达式）

### 7.1 最小规则

```yaml
id: hello-world
info:
  name: Hello World
  author: zhizhuo
  created: 2025/04/01
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body.ibcontains(b"hello")
expression: r0()
```

### 7.2 可用对象

| 对象 | 来源 | 主要字段 |
|------|------|---------|
| `request` | proto.Request | `method`、`url.{scheme,domain,host,port,path,query}`、`headers`、`body`、`raw`、`raw_header` |
| `response` | proto.Response | `status`、`headers`、`body`、`raw`、`raw_header`、`icon_hash`、`latency` |
| `reverse` | proto.Reverse（需 `newReverse()`） | `url`、`domain`、`ip` + `wait(timeout)` 方法 |

### 7.3 高频函数

```
# 字符串匹配
response.body.ibcontains(b"特征")        # 字节、忽略大小写（推荐）
response.body.bcontains(b"特征")         # 字节、区分大小写
response.headers["Server"].contains("X") # 字符串、区分大小写

# 正则
response.raw_header.bmatches(b"Server:\\s*nginx/\\d+")

# 编码
md5("xxx") == "..."
base64("xxx")
faviconHash(response.body) == -1234567890

# 组合
r0() && (r1() || r2())
```

### 7.4 变量与 payload

```yaml
set:
  num: randomInt(800000000, 1000000000)
  payload: randomLowercase(20)

rules:
  r0:
    request:
      path: /{{num}}.php
      body: '{"data":"{{payload}}"}'
```

`{{var}}` 在 `formatPath` / `formatBody` 中被 `SetVariableMap` 替换；CEL 表达式内则可直接引用 `num` / `payload`。

### 7.5 反连平台

```yaml
set:
  r1: newReverse()          # 或 newJNDI()
rules:
  r0:
    request:
      path: /?url={{r1.url}}
    expression: r1.wait(5)   # 等待 5 秒，看反连平台是否记录到回连
```

SDK 使用 `sdk.WithReverseConfig(sdk.ReverseConfig{...})` 配置当前实例的 Ceye / JNDI 服务；Runner 对应 `ScanConfig.Reverse`。规则执行者按值持有配置，CEL 查询使用所属实例的客户端和扫描 context。

---

## 八、并发模型详解

```
                          ┌──────────────────────────────────────────┐
                          │ executeScan(URL 池, 默认 5 并发)         │
                          │  ┌────────────────┐  ┌────────────────┐ │
                          │  │ URL worker 1   │  │ URL worker N   │ │
                          │  │ ┌────────────┐ │  │ ┌────────────┐ │ │
                          │  │ │ GetBaseInfo│ │  │ │ GetBaseInfo│ │ │
                          │  │ └────────────┘ │  │ └────────────┘ │ │
                          │  │       │        │  │       │        │ │
                          │  │       ▼        │  │       ▼        │ │
                          │  │ 提交 N 条规则  │  │ 提交 N 条规则  │ │
                          │  │ (limiter 回压) │  │ (limiter 回压) │ │
                          │  └───────┬────────┘  └───────┬────────┘ │
                          └──────────┼───────────────────┼──────────┘
                                     │                   │
                                     └─────────┬─────────┘
                                               ▼
                          ┌──────────────────────────────────────────┐
                          │ *RulePool (Runner 实例, 默认 200 总容量) │
                          │  ┌─────────┐ ┌─────────┐    ┌─────────┐  │
                          │  │ worker  │ │ worker  │... │ worker  │  │
                          │  │ 处理 1  │ │ 处理 1  │    │ 处理 1  │  │
                          │  │ RuleTask│ │ RuleTask│    │ RuleTask│  │
                          │  └─────────┘ └─────────┘    └─────────┘  │
                          │                                          │
                          │  每个 worker: evaluateFingerprint         │
                          │  ├─ 缓存命中 → 直接 CEL 求值              │
                          │  └─ 未命中 → SendRequest → CEL 求值       │
                          └──────────────────────────────────────────┘
```

**关键设计**：

1. **规则池按 Runner 实例隔离**：同一 Runner 内所有 URL 共享一个 RulePool，避免「每 URL 独占 200 协程」造成的线程爆炸
2. **信号量回压**：URL 协程提交规则时通过 `limiter chan struct{}` 限制在途任务数（容量 = 规则线程数 × 2），保护内存
3. **结果通道收集**：使用 `chan *FingerMatch` 异步收集结果，由独立 collector goroutine 写入 slice，避免锁竞争
4. **WaitGroup 同步**：每个 URL 的规则任务完成后通过 `wg.Wait()` 同步，再处理下一目标

---

## 九、关键扩展点

### 9.1 添加新的 CEL 函数

修改 `pkg/cel/celprogram.go` 的 `functionEnvOptions` 切片：

```go
cel.Function("myFunc",
    cel.Overload("myFunc_string",
        []*cel.Type{cel.StringType}, cel.StringType,
        cel.UnaryBinding(func(v ref.Val) ref.Val {
            s := v.(types.String)
            return types.String(strings.ToUpper(string(s)))
        }),
    ),
),
```

### 9.2 添加新的协议类型

1. 在 `pkg/finger/runner.go` 的 `SendRequest` switch 中新增分支
2. 在 `pkg/network/` 实现客户端
3. 通过 `network.RawParse` 或类似函数封装为 `proto.Request` / `proto.Response`

### 9.3 添加新的输出格式

- **CLI 入口**：修改 `utils/output/file.go` 的 `WriteFingerprints`，新增 `opts.Format == "your_format"` 分支即可。
- **SDK 入口**：实现 `sdk.Writer` 接口（`Write` + `Close`），通过 `sdk.WithWriter(your)` 注入；
  也可直接基于 `sdk.NewFileWriter` 扩展新的序列化分支。

### 9.4 自定义指纹库目录

CLI: `gxx -u xxx -pf /path/to/yamls`

SDK:
```go
engine, _ := sdk.NewEngine(ctx, sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "/path/to/yamls"}))
```

---

## 十、编译与发布

```bash
# 本地构建（loader.go，不传 build tag，依赖 ./fingerYaml 目录）
make build

# 嵌入指纹库构建（embed.go，-tags embed，单文件部署）
make build-embed

# 跨平台构建（依赖 build.sh，输出 build/*.zip）
make release           # 6 个平台 × 不嵌入
make release-embed     # 6 个平台 × 嵌入

# goreleaser 模式（CI 推荐，输出含校验和的归档）
goreleaser release --snapshot --clean
```

支持的平台：darwin/{amd64,arm64}、linux/{amd64,arm64}、windows/{amd64,arm64}。

通过 `ldflags -X` 注入版本号、作者、构建时间到 `cmd/cli/banner.go` 的全局变量。

---

## 十一、待改进 / 注意事项

1. `*runner.Runner` 管理当前实例的 RulePool、Cache、HTTPClient 和反连配置；SDK 日志使用实例 `slog.Logger` 与扫描 context，不修改 CLI 的日志级别
2. favicon hash 使用当前 HTTP 客户端的有界 LRU，键包含 URL、代理、请求头和 Cookie 摘要；有效图标读取到 EOF，失败不保存前缀哈希；响应体在请求结束时关闭
3. 基础响应保持只读所有权；缓存保留完整已读取字段，超过字节预算时不缓存。正文上限和缓存预算分别管理读取范围与复用容量
4. `DisableKeepAlives` 默认 **false**（`sdk.WithDisableKeepAlives`）；遇 "Unsolicited response" 等兼容性问题时再显式关闭 Keep-Alive
5. `utils/output/file.go` 的全局 `mu sync.Mutex` 仅服务于 CLI 路径；SDK 使用 `sdk.Writer`。同一自定义 Writer 或输出路径被多个实例显式传入时，调用方负责共享资源的生命周期
6. CSV 输出未使用 `strings.Replace` 转义 quote 字符（依赖 `encoding/csv` 自动处理），但 Headers 字段做了 `\n → \\n` 的人工转义，建议统一策略
7. YAML 规则解析使用调用内状态；并发加载、直接解码 `Rule` 和重复规则名称均有回归用例

---

## 十二、测试

| 命令 | 说明 |
|------|------|
| `go test ./test/...` | 默认回归（本地 `httptest`，不依赖外网） |
| `go test -tags=integration ./test/...` | 外网集成（`engine_integration_test.go`，需网络可达） |
| `go test -tags=bench ./test/...` | 性能压测（`ants_test.go`，耗时长） |

---

## 十三、快速上手 Checklist

**作为使用者**：

- [ ] 读 `README.md` 了解 CLI 用法
- [ ] 跑 `example/basic_scan/main.go` 验证 SDK 集成
- [ ] 读 `sdk/sdk.md` 学习 API 调用

**作为开发者**：

- [ ] 跑 `go test ./test/...` 确认本地回归通过
- [ ] 读 `cmd/main.go` → `cli/cmd.go` → `pkg/runner/runner.go` 串通主流程
- [ ] 读 `pkg/runner/scan.go` 理解单目标扫描的完整步骤
- [ ] 读 `pkg/runner/fingerprint.go` 的 `evaluateFingerprint` 理解指纹评估机制
- [ ] 读 `pkg/cel/cel.go` + `celprogram.go` 理解表达式引擎
- [ ] 读 `pkg/runner/cache.go` 理解缓存策略
- [ ] 读 `pkg/runner/pool.go` 理解规则池抽象
- [ ] 看 `fingerYaml/jiajiu/` 下任意 YAML 文件理解规则编写

**作为指纹规则编写者**：

- [ ] 读 `docs/指纹规则格式说明.md`
- [ ] 读 `docs/指纹开发快速参考.md`
- [ ] 用 `gxx -u <target> -p <your.yaml> --debug` 调试单个规则
