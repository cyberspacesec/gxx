# API 扫描示例（v3.0 Engine API）

本示例演示 `(*Engine).GetBaseInfo` 与 `(*Engine).Scan` 的组合使用 + sentinel error 处理。

## 运行

```bash
cd example/api_scan_baidu
go run main.go
```

## 核心点

```go
// 1. 创建 Engine
engine, _ := sdk.NewEngine(ctx,
    sdk.WithFingerOptions(options),
    sdk.WithTimeout(5*time.Second),
)
defer engine.Close()

// 2. 仅基础信息（不跑指纹）
baseInfo, err := engine.GetBaseInfo(ctx, target)

// 3. 完整指纹识别
result, err := engine.Scan(ctx, target)
```

## Sentinel Error 处理

```go
result, err := engine.Scan(ctx, target)
switch {
case errors.Is(err, sdk.ErrEngineClosed):
    // 引擎已关闭
case errors.Is(err, sdk.ErrEmptyTarget):
    // 跳过空目标
case errors.Is(err, sdk.ErrEmptyResult):
    // 目标不可达 / 防火墙拦截
case err != nil:
    // 其他错误
}
```
