# 技术栈识别示例（v3.0 Engine API）

本示例演示 `(*Engine).WappalyzerScan` 与 `(*Engine).GetBaseInfo` 的复用。

## 运行

```bash
cd example/wappalyzer_scan
go run main.go
```

## 核心代码

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithTimeout(10*time.Second),
)
defer engine.Close()

// 方式一：从 GetBaseInfo 拿 TechStack（一次请求获取所有基础信息）
baseInfo, _ := engine.GetBaseInfo(ctx, target)
ts := baseInfo.TechStack

// 方式二：仅技术栈识别
ts, _ := engine.WappalyzerScan(ctx, target)
```

## TechStack 字段

```go
type TechStack struct {
    WebServers           []string  // 如 [Nginx, OpenResty]
    ProgrammingLanguages []string  // 如 [PHP, Node.js]
    WebFrameworks        []string  // 如 [Spring Boot, Laravel]
    JavaScriptFrameworks []string  // 如 [Vue.js, React]
    JavaScriptLibraries  []string  // 如 [jQuery, lodash]
    Security             []string  // 如 [HSTS, CSP]
    Caching              []string  // 如 [Varnish]
    ReverseProxies       []string  // 如 [Cloudflare]
    StaticSiteGenerator  []string
    HostingPanels        []string
    Other                []string
}
```

## 单 Engine 多目标复用

同一个 `*Engine` 可在不同 goroutine 中并发调用，无需重复初始化指纹库：

```go
var wg sync.WaitGroup
for _, target := range targets {
    wg.Add(1)
    go func(t string) {
        defer wg.Done()
        ts, _ := engine.WappalyzerScan(ctx, t)
        // 处理 ts
    }(target)
}
wg.Wait()
```
