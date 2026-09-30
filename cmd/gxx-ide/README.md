# GXX IDE — 指纹规则可视化开发工具

详细介绍请见根目录 [GXX-IDE.md](../../GXX-IDE.md)。

## 快速命令

```bash
# 一次性安装依赖（需 wails CLI / Node 20.19+ 或 22.12+）
go install github.com/wailsapp/wails/v2/cmd/wails@latest
go install github.com/swaggo/swag/cmd/swag@latest
make gui-deps      # 在主仓库根目录运行

# 生成 swagger
make swagger

# 开发热重载
make dev-gui

# 单平台构建
make build-gui

# 跨平台批量打包（产物写入仓库根 build/，与 gxx CLI 同目录）
make package-gui
# 例如 build/gxx-ide_mac_arm64_1.1.9.zip
```

## 仅启动后端 API

不打开 GUI 窗口，仅暴露 Gin HTTP server，适合集成 / CI 场景：

```bash
cd cmd/gxx-ide
go run . -headless -port 9527
# 浏览器访问 http://127.0.0.1:9527/swagger/index.html
```

## API 会话认证

`/api/v1/*` 需要 `Authorization: Bearer <令牌>`。桌面窗口通过 Wails 原生绑定获取当前会话令牌；`./ide-dev.sh all` 自动为 API 和 Vite 配置同一会话。Swagger 的 Authorize 中填写完整的 `Bearer <令牌>`。

独立启动 API 时可设置 `GXX_IDE_TOKEN`；未设置时生成随机令牌并写入权限为 `0600` 的临时文件，启动日志只显示文件路径。正常退出时删除该文件。分别启动 Vite 与 API 时，将 `VITE_GXX_IDE_TOKEN` 设为相同令牌；该变量仅用于本机开发环境。

接口仅监听本机地址，浏览器来源限本机与 Wails。指纹库文件须位于通过默认目录或目录列表选定的根目录内，仅允许 `.yaml` / `.yml` 普通文件，单文件上限 4 MiB；拒绝通过符号链接访问目录外的文件。
