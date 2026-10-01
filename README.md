# GXX - 基于YAML规则的指纹识别引擎

GXX 是一款高性能指纹识别工具，基于 YAML 配置的 CEL 表达式规则进行目标系统识别。支持 HTTP/HTTPS、TCP、UDP 协议，可进行大规模批量目标扫描。

## 主要特性

- **YAML 规则引擎** - 基于 CEL 表达式的指纹匹配，规则简洁强大
- **高性能并发** - ants 协程池 + 两级并发（URL 级 + 规则级），支持大规模目标
- **多协议支持** - HTTP/HTTPS、TCP、UDP、Raw HTTP
- **技术栈识别** - 内置 Wappalyzer 引擎识别网站技术组件
- **多格式输出** - TXT / CSV / JSON，支持 Unix Domain Socket 实时推送
- **SDK 接口** - 独立 SDK 包，所有对外类型自包含，支持 `context.Context`；自带实例化 Writer 抽象（`WithOutputFile` / `WithSockOutputFile` / `WithWriter`），多 Engine 互不影响
- **内存优化** - 有界 CEL / 正则缓存 + 响应复用 + 请求缓存字节预算
- **GXX IDE** - 可视化指纹规则编辑器（Wails + Gin + Vue 3 + Monaco），
  内置 HTTP / CEL 自定义语法高亮、请求测试、逐 rule 调试、Swagger API，
  详见 [GXX-IDE.md](GXX-IDE.md)

构建需要 **Go 1.25.0+**。IDE 前端需要 Node.js 20.19+ 或 22.12+。

## 快速开始

### CLI 使用

```bash
# 扫描单个目标
gxx -u https://example.com

# 从文件批量扫描
gxx -f targets.txt

# 使用代理
gxx -u https://example.com --proxy http://127.0.0.1:8080

# 输出为 CSV（格式由扩展名自动识别）
gxx -u https://example.com -o results.csv

# JSON 输出
gxx -u https://example.com -o results.json --json

# 调试模式
gxx -u https://example.com --debug

# 设置规则并发线程数
gxx -u https://example.com -rt 500
```

### SDK 使用

在调用方的 Go 模块内安装 SDK：

```bash
go get github.com/cyberspacesec/gxx/v2/sdk@v2.0.0
```

发布包见 [GitHub Releases](https://github.com/cyberspacesec/gxx/releases)，自动测试与发布流程见 [构建与发布](docs/构建与发布.md)。

```go
package main

import (
    "context"
    "fmt"
    "github.com/cyberspacesec/gxx/v2/sdk"
    "log"
)

func main() {
    ctx := context.Background()

    engine, err := sdk.NewEngine(ctx,
        sdk.WithFingerOptions(sdk.FingerOptions{}),
        sdk.WithTimeoutSeconds(10),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    result, err := engine.Scan(ctx, "https://example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("URL: %s  状态码: %d  标题: %s\n", result.URL, result.StatusCode, result.Title)
    for _, m := range result.Matches {
        fmt.Printf("  - %s (%s)\n", m.Info.Name, m.Info.ID)
    }
}
```

详细 SDK 文档参见 [sdk/sdk.md](sdk/sdk.md)。

规则导入使用 `RuleCatalog`，识别结果分别返回作者、厂商、来源验证声明、样本记录、产品版本及可定位的命中证据；`Products` 按规范产品目录归并并保留命中规则。字段约定、数据覆盖范围和测试方法见[指纹数据与验证](docs/指纹数据与验证.md)。

favicon 候选、重定向资源解析、内联图标哈希与 ICP 备案识别的范围和限制参见 [网站元数据识别](docs/网站元数据识别.md)。

## 命令行参数

### 输入选项
| 参数 | 说明 |
|------|------|
| `-u, --url` | 目标 URL/主机（可指定多个） |
| `-f, --file` | 目标列表文件（每行一个） |
| `-t, --threads` | URL 并发线程数（默认 5） |
| `-rt, --rulethreads` | 规则并发线程数（默认 200，最大 5000） |

### 输出选项
| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出文件路径（txt/csv/json） |
| `--json` | JSON 格式输出 |
| `--sock` | Unix Domain Socket 实时输出路径 |

### 调试选项
| 参数 | 说明 |
|------|------|
| `--proxy` | HTTP/SOCKS5 代理 |
| `-p` | 测试单个 YAML 文件 |
| `-pf` | 测试指定目录的 YAML 文件 |
| `--debug` | 开启调试模式 |
| `--no-file-log` | 禁用文件日志 |
| `--timeout` | 请求超时（秒，默认 3） |

## 项目结构

```
gxx/
├── cmd/                       # CLI 入口
│   ├── main.go               # 主程序
│   └── cli/                  # 命令行处理
├── sdk/                       # SDK 对外接口（所有对外类型均在此定义）
│   ├── sdk.go                # 业务 API
│   ├── sdk.md                # SDK 文档
│   └── debug/                # 运维/调试 API（内存监控、GC等）
├── pkg/                       # 核心引擎
│   ├── cel/                  # CEL 表达式引擎（有界环境与 Program 缓存）
│   ├── finger/               # 指纹规则解析与执行
│   ├── runner/               # 扫描调度器（工作池、缓存、监控）
│   ├── network/              # 网络请求层（HTTP/TCP/UDP）
│   └── wappalyzer/           # Wappalyzer 技术栈识别
├── types/                     # 公共类型定义
├── utils/                     # 基础设施
│   ├── logger/               # 日志系统（延迟格式化，高并发友好）
│   ├── output/               # 多格式输出
│   ├── common/               # 通用工具
│   ├── config/               # 配置管理
│   └── proto/                # Protobuf 协议定义
├── fingerYaml/                # 内置指纹规则库（embed.go / loader.go）
└── example/                   # 示例代码
    ├── basic_scan/           # 基本扫描
    ├── api_scan_baidu/       # API 调用示例
    ├── file_target_scan/     # 文件批量扫描
    ├── proxy_scan/           # 代理扫描
    └── wappalyzer_scan/      # 技术栈识别
```

## 执行流程

```
目标输入 → 存活探测(GET /) → 基础信息提取 → 缓存预热 → 规则并发匹配 → 结果输出
                                 │                         │
                          标题/证书/ICP/Wappalyzer    CEL表达式评估
                                                     (2348条规则×200并发)
```

1. **存活探测**：对目标发起 GET / 请求，获取标题、证书、服务器信息、ICP 备案号、Wappalyzer 技术栈
2. **缓存预热**：将基础响应写入缓存，后续规则匹配时直接复用（TTL + W-TinyLFU 自适应淘汰；普通构建优先使用磁盘 `fingerYaml/`，缺失时回退内置规则；`make build-embed` 的默认库使用内置规则）
3. **规则匹配**：2348 条指纹规则通过 Runner 实例内的 `*RulePool`（默认 200 并发）并行执行 CEL 表达式评估
4. **结果输出**：匹配结果实时输出到控制台 + 文件 + Socket

## 性能与资源管理

引擎复用经过类型检查的 CEL 程序；每个程序只保存实际使用的函数。环境、程序和正则缓存均有容量上限，环境缓存使用单分片以避免工作集被过早淘汰。响应归一化结果按单次扫描共享，请求缓存默认使用 64 MiB 估算字节预算；这些预算不等于进程内存硬上限。

HTTP Keep-Alive、规则快照和技术栈规则索引可复用。静态指纹在加载时生成连续的不可变执行清单，包含 CEL 程序和调度条件；独占求值状态通过对象池复用，归还时清除规则结果、动态声明和请求引用。仅依赖已缓存首页、没有动态声明、推导循环或等待的规则可按最多 8 条合并调度，每条仍独立评估、计数并处理异常。请求、循环、等待和反连沿用独立任务，规则并发与在途指纹预算保持不变。无推导循环的表达式直接求值，含循环的表达式保留中断检查和成本限制，I/O 与等待函数始终使用扫描 context。

技术栈识别用字段索引及包含或分支的必要字面量集合筛选候选，再使用上游解析器判定。字面量索引在构造期和运行期均使用连续数组，编译正则采用 512 条有界工作集缓存。全部规则保持可用，缓存淘汰后可重新编译。较大响应反复执行字节包含查询时，可共享 8 KiB 的四字节片段位图；预筛选只排除必然不匹配的条件，候选仍由原始包含函数判定。位图按需构造，随机二进制内容导致饱和时回退，相关响应数据共用单次扫描 8 MiB 的估算缓存预算。

请求缓存按扫描作用域隔离，并共享 Engine 的容量预算与维护协程；同一目标的并发扫描不会互相覆盖响应或清理缓存。内部结构化缓存键避免重复散列，同次扫描内可缓存的相同普通 GET 请求合并执行。内部响应以只读消息共享，公共缓存写入仍复制调用方数据，缓存保留完整字段，超过容量预算时跳过缓存。实例请求头在构造时复制，规则覆盖时才建立独立请求头。页面正文读取保持 512 KiB 上限：已知长度使用有界提示，未知长度使用 32 KiB 暂存块并一次合并，暂存池最多保留 1 MiB；返回正文独占数组，Raw 使用独立数组。图标使用独立的完整流读取，哈希缓存归当前实例持有。关闭 Engine 会取消并等待在途操作，再释放实例资源。大批量任务可使用 `ScanCallback` 消费结果，或使用 `ScanIterator` 按并发预算读取目标；CLI 逐条输出后只保留汇总计数，目标去重集合仍随唯一目标数增长。

### 全量指纹扫描测量

2026-09-30，macOS / Apple M2 / Go 1.25.0。使用完整的 2,348 条指纹、默认 200 个规则工作协程和本地 Apache / WordPress 阳性靶场，对比当日保存的基线实现与批量调度实现；双方工具链、依赖和输入一致。每个目标预热 1 次后，小响应与带请求头场景扫描 100 次，大响应与 Unicode 场景 40 次，复杂 HTML 场景 20 次；5 目标并发分别扫描 100 次和 80 次。交替运行 3 组，以下为组均值的中位数，箭头表示基线到批量调度实现。RSS 包含进程冷启动，分配量包含同进程的本机靶场；这些数据不包含 IDE WebView，也不等同于生产网络吞吐。

| 负载 | 每目标累计分配量（MiB） | 每目标耗时（ms） | 进程峰值 RSS（MiB） |
|---|---:|---:|---:|
| 单目标、小响应 | 1.00 → 0.97 | 5.78 → 5.31 | 87.02 → 85.20 |
| 256 KiB 分块传输响应 | 37.33 → 16.38 | 42.56 → 39.00 | 120.58 → 102.67 |
| 256 KiB 已知长度响应 | 24.22 → 16.43 | 39.36 → 41.15 | 109.64 → 104.88 |
| 5 目标并发、小响应 | 0.99 → 0.96 | 3.98 → 3.53 | 89.52 → 91.98 |
| 5 目标并发、256 KiB 响应 | 37.29 → 16.53 | 18.31 → 12.17 | 171.06 → 154.86 |
| 含 Unicode 大小写等价字符 | 1.02 → 0.98 | 4.76 → 4.22 | 81.06 → 79.70 |
| 复杂 HTML，约 500 KiB | 79.90 → 35.96 | 164.58 → 165.59 | 126.34 → 117.83 |
| 16 个实例请求头 | 4.15 → 1.18 | 7.85 → 6.67 | 89.23 → 84.59 |

并发场景的耗时是批次总时间除以目标数，反映吞吐，不是每个请求的独立延迟。累计分配量也不等于同时占用的内存。已知长度大响应耗时中位数增加 4.5%，复杂 HTML 增加 0.6%；并发小响应 RSS 增加 2.8%。部分 GC 后存活堆增加，例如已知长度大响应为 21.02 → 24.53 MiB，复杂 HTML 为 26.32 → 28.22 MiB；有限测量不能证明所有负载的所有指标都下降。

全部 2,348 条指纹及 6,029 个表达式保留，八类负载的完整识别输出前后一致。连续 1,000 次全量扫描结果一致，每 50 次采样的 GC 后存活堆为 21.71–22.27 MiB，关闭后协程数回到 5。有限测试不能证明所有产品规则都准确或永远不会泄漏。

授权测试目标完成全部 2,348 条规则任务，执行失败为 0，返回 HTTP 200 与 Nginx 技术栈；该目标没有内置产品指纹命中。

技术栈适配器覆盖 4,977 种 HTTP 模式，314,602 个上游确认正例通过必要字面量检查；另有完整输出、ASCII 全部大小写等价类、Unicode、HTML 实体、缓存淘汰与并发回归。基于变化响应的并发测试验证同一 URL 的两个扫描不会串用结果。

复核命令：

```bash
GOTOOLCHAIN=go1.25.0 go test -race ./...
GOTOOLCHAIN=go1.25.0 go test -tags embed ./sdk ./pkg/cel ./pkg/runner ./pkg/wappalyzer
GOTOOLCHAIN=go1.25.0 go test ./sdk -run '^$' -bench 'BenchmarkFullFingerprints|BenchmarkRuleConcurrency' -benchmem -benchtime=30x
```

### 响应处理与结果内存

标题提取消费只读正文的字节视图，只为命中的字段建立字符串；字符集回退仍使用原有转换流程。标题与 ICP 备案号独立持有返回字段，结果长期保留时不引用完整 HTML 或 i18n 脚本。DOM / i18n 正则只在必要字符存在时运行，脚本按原有顺序消费到第一个适用项。合法 UTF-8 正文缺少“号”时可直接排除备案号候选，网络正文入口无需先复制整页为字符串。图标哈希逐块编码并累计，暂存区固定为 2,465 字节；公开 `StandBase64` 返回独立数组，行宽、补齐和最终换行遵循原有格式。图标成功缓存和失败后备请求行为保持一致。

2026-09-30，以当日保存的批量调度实现为基线，同样使用 Go 1.25.0、全部 2,348 条指纹和固定本机响应交替测量 3 组。256 KiB 分块响应耗时中位数为 37.96 → 27.20 ms，已知长度响应为 37.23 → 26.49 ms，5 目标并发大响应的批次均摊耗时为 17.05 → 11.58 ms，复杂 HTML 为 165.66 → 106.83 ms。复杂 HTML 每目标累计分配量为 35.90 → 30.32 MiB；32 个短标题与 32 个短备案号的独立内存回归，GC 后存活堆增量为 32.54 MiB → 7.37 KiB。512 KiB 图标哈希的额外分配为约 3.34 MiB → 2.70 KiB，此数不包含原始响应正文。

八类负载的完整输出对照一致，静态标题、DOM、i18n 和 GB18030 四种整库回放的完整 SDK 输出及 45 次请求也一致。上述为有限测试，不是所有网站的等价证明。小响应、并发小响应和请求头场景的耗时分别增加 5.2%、6.9% 和 15.1%；256 KiB 分块响应峰值 RSS 为 105.59 → 111.16 MiB，并发大响应为 159.52 → 153.56 MiB。分配量、结果存活堆和进程峰值 RSS 是不同指标，不能据此宣称所有场景内存与耗时都下降。

SDK 的缓存、并发、日志与生命周期约定见 [SDK 使用文档](sdk/sdk.md)。

网站元数据的读取范围、同类型产品默认值、SDK 实例隔离及历史基线测量见[资源读取与实例隔离](docs/资源读取与实例隔离.md)；页面正文当前保持 512 KiB，有效 HTTP 图标使用完整流读取。

## 指纹规则格式

```yaml
id: web-application

info:
  name: Web应用识别
  author: 作者名
  description: 识别特定Web应用

rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.status == 200 && response.body.ibcontains(b"特征字符串")

expression: r0()
```

详细规则语法参考 [docs/指纹规则格式说明.md](docs/指纹规则格式说明.md)。

## 编译构建

```bash
# Makefile 构建
make build          # 优先磁盘指纹库，缺失时使用内置规则
make build-embed    # 嵌入指纹库（单文件）
make release        # 构建发布包

# 手动编译（二选一）
CGO_ENABLED=0 go build -ldflags "-w -s" -o gxx cmd/main.go              # 优先磁盘库，支持内置规则回退
CGO_ENABLED=0 go build -tags embed -ldflags "-w -s" -o gxx cmd/main.go  # embed.go 单文件内嵌指纹

# 构建脚本
chmod +x build.sh && ./build.sh
```

## 示例代码

| 示例 | 说明 |
|------|------|
| [basic_scan](example/basic_scan/) | 基本单目标扫描 |
| [api_scan_baidu](example/api_scan_baidu/) | API 集成示例 |
| [file_target_scan](example/file_target_scan/) | 文件批量扫描 |
| [proxy_scan](example/proxy_scan/) | 代理扫描 |
| [wappalyzer_scan](example/wappalyzer_scan/) | 技术栈识别 |

## 免责声明

本工具仅用于授权的安全测试和研究目的。使用者应遵守相关法律法规，未经授权不得对目标系统进行扫描。工具作者不对任何滥用行为负责。

## 许可证

[MIT License](LICENSE)
