# 文件批量扫描示例（v3.0 Engine API + ScanCallback）

本示例演示 `(*Engine).ScanCallback` 流式回调批量扫描。

## 优势

相比 v2.0 自己写 `sync.WaitGroup + sync.Mutex + chan` 的方式：
- 不需要等所有目标完成才能拿到结果（边扫边处理）
- 不需要自己管理 goroutine pool（`WithURLConcurrency` 控制并发）
- 回调返回 `false` 可主动取消整批扫描

## 运行

```bash
cd example/file_target_scan
go run main.go
```

## 核心代码

```go
engine, _ := sdk.NewEngine(ctx,
    sdk.WithFingerOptions(options),
    sdk.WithURLConcurrency(20),    // 同时扫描 20 个目标
    sdk.WithRuleConcurrency(200),  // 单目标内部规则并发
)
defer engine.Close()

cb := func(r *sdk.TargetResult) bool {
    fmt.Printf("✓ %s [%d] matches=%d\n", r.URL, r.StatusCode, len(r.Matches))
    return true // false 取消整批
}

err := engine.ScanCallback(ctx, targets, cb)
```

## 输入文件格式

`targets.txt`，每行一个目标：

```
example.com
github.com
https://www.baidu.com
192.168.1.1:8080
```
