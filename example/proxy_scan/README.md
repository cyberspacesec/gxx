# 代理扫描示例（每主机限速）

本示例演示通过 HTTP/SOCKS5 代理扫描 + per-host 速率限制。

## 运行

```bash
cd example/proxy_scan
go run main.go
```

## 核心代码

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithFingerOptions(options),
    sdk.WithProxy("http://127.0.0.1:8080"),  // HTTP 代理
    // sdk.WithProxy("socks5://127.0.0.1:1080"), // SOCKS5 代理
    sdk.WithTimeout(10*time.Second),
    sdk.WithRateLimit(20, 30),  // 20 QPS / burst 30
)
defer engine.Close()
```

## per-host 限流原理

每个目标 host 持有独立的令牌桶（`golang.org/x/time/rate.Limiter`），LRU 缓存最近 512 个 host：

- 桶按 `qps` 速率匀速产生令牌
- 每次 Scan 阻塞直到 host 桶有可用令牌
- 不同 host 互不影响，避免高并发把单个目标打挂
