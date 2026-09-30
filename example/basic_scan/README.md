# 基本扫描示例（v3.0 Engine API）

本示例展示 GXX SDK 最基本的使用方式，通过 `*sdk.Engine` 实例对单 / 多个目标进行指纹识别。

## 功能特点

- 用 `sdk.NewEngine` + functional options 构造引擎
- `defer engine.Close()` 释放资源
- 用 `(*Engine).Scan` 对单目标做完整指纹识别
- 提取技术栈、证书、ICP 备案号

## 运行

```bash
cd example/basic_scan
go run main.go
```

## 核心代码

```go
engine, err := sdk.NewEngine(ctx,
    sdk.WithFingerOptions(options),
    sdk.WithTimeout(5 * time.Second),
    sdk.WithRuleConcurrency(200),
)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

result, err := engine.Scan(ctx, "https://example.com")
```

## 自定义参数

```go
sdk.WithTimeout(10*time.Second)     // 请求超时
sdk.WithProxy("http://127.0.0.1:8080") // 代理
sdk.WithRuleConcurrency(500)        // 规则并发
sdk.WithCacheSize(4096)             // 缓存条目数
sdk.WithRateLimit(50, 100)          // per-host 限流
sdk.WithMemoryMonitor(true)         // 启用内存监控
```

## 进阶

参考其他示例：
- `example/file_target_scan/`：批量扫描 + 流式回调
- `example/proxy_scan/`：代理 + 限流
- `example/wappalyzer_scan/`：仅技术栈识别
