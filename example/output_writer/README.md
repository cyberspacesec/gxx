# output_writer — SDK Writer 抽象示例

演示如何在 SDK 中使用 v3 新增的 `Writer` 能力：

- `sdk.WithOutputFile` 把结果以 JSON Lines 形式写入本地文件
- `sdk.WithWriter` 注入自定义 `Writer`（这里实现一个简易计数器）

Writer 与 `ScanCallback` 可以同时启用：Engine 在每完成一个目标后，
会先把结果派发给所有 Writer，再触发回调。

## 运行

```bash
cd example/output_writer
go run main.go
```

执行结束后会在当前目录看到 `results.json`，每行一条 JSON 形式的 `TargetResult`。

## 关键代码

```go
counter := &countingWriter{} // 任意实现 sdk.Writer 接口的类型

engine, _ := sdk.NewEngine(ctx,
    sdk.WithOutputFile("results.json", sdk.FormatJSON),
    sdk.WithWriter(counter),
)
defer engine.Close()

// Scan / ScanCallback / ScanBatch 完成单目标后都会派发到 Writer
```

## 内置 Writer

| 工厂 | 说明 |
|------|------|
| `sdk.NopWriter()` | 不写任何内容（默认） |
| `sdk.NewFileWriter(path, format)` | 写入文件，支持 `FormatTXT` / `FormatCSV` / `FormatJSON` |
| `sdk.NewSockWriter(path)` | 监听 Unix domain socket，向所有连接广播 JSON Lines |
| `sdk.NewMultiWriter(writers...)` | 串联多个 Writer，错误用 `errors.Join` 收集 |

`WithOutputFile` / `WithSockOutputFile` / `WithWriter` 多次调用会被自动合并到 `MultiWriter`。
