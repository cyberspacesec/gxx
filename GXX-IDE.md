# GXX IDE — 指纹规则可视化开发工具

> 完全独立的 Wails v2 桌面 + Gin HTTP API 双形态工具，
> 为 GXX 指纹规则的编写 / 调试 / 库管理提供一站式 IDE 体验。

---

## 一、定位

GXX IDE 是 **GXX 指纹引擎的伴随工具**：

- 桌面端用户可在 GUI 中编辑指纹、发请求测试、查看 r0/r1 中间结果；
- 第三方系统可以直接调用其 HTTP API（含 Swagger 文档）集成扫描流水线；
- 通过 Vue 3 + Monaco Editor 提供现代化的代码编辑体验，自动补全 CEL 函数与 `request.*` / `response.*` 字段；
- 完全独立于主仓库的 Go module，**主项目构建 / 二进制体积不受任何影响**。

---

## 二、技术栈

| 层 | 选型 | 说明 |
|----|------|------|
| 桌面外壳 | [Wails v2](https://wails.io/) | webview 嵌入式 GUI，支持 macOS / Windows 客户端打包 |
| HTTP 后端 | [Gin](https://gin-gonic.com/) | 高性能 HTTP 框架，分层 handler / service / model |
| API 文档 | [swaggo/swag](https://github.com/swaggo/swag) + [gin-swagger](https://github.com/swaggo/gin-swagger) | 通过注释生成 OpenAPI 2.0 |
| 前端框架 | Vue 3 + Vite + TypeScript | Composition API + `<script setup>` |
| 编辑器 | Monaco Editor + [Shiki](https://shiki.style) | YAML 高亮 + CEL Monarch + HTTP TextMate grammar（@shikijs/monaco）+ 自动补全 |
| 状态管理 | Pinia | Vue 官方推荐 |
| 路由 | Vue Router | hash 模式适配 webview |
| HTTP 客户端 | axios | 统一拦截器消费 `{code, message, data}` |

---

## 三、目录结构

```
cmd/gxx-ide/                            # 独立 Go module（go.mod 与主项目隔离）
├── go.mod                              # require gin/swag/wails，replace github.com/cyberspacesec/gxx => ../..
├── main.go                             # 入口：启动 Gin server (goroutine) + Wails GUI
├── wails.json                          # Wails 项目配置
├── docs/                               # swag init 生成的 OpenAPI 文档（含占位）
│   └── docs.go
├── internal/                           # 私有代码（Go 语言惯例，禁止外部 import）
│   ├── response/                       # 统一 {code, message, data} 响应封装
│   │   └── response.go
│   ├── middleware/                     # Gin 中间件
│   │   └── middleware.go               # Logger / Recovery / CORS / 404·405
│   ├── model/                          # 数据模型 + swagger 标签
│   │   └── model.go
│   ├── service/                        # 业务逻辑
│   │   ├── request_service.go
│   │   ├── yaml_service.go
│   │   ├── finger_service.go
│   │   └── library_service.go
│   ├── handler/                        # HTTP handler + swagger 注释
│   │   └── handler.go
│   ├── router/                         # 路由组合
│   │   └── router.go
│   └── server/                         # Gin server 生命周期 + Engine() 暴露给 Wails
│       └── server.go
├── scripts/
│   ├── packager/                       # 独立打包配置程序
│   │   └── main.go                     # 每平台清理 build/bin/、支持 .app bundle 目录拷贝
│   └── wails-go                        # wails -compiler 用的 Go 包装脚本
│                                       # （macOS 注入 UniformTypeIdentifiers 框架链接）
└── frontend/                           # Vue 3 + Vite + TS（create-vue 官方目录结构）
    ├── package.json
    ├── vite.config.ts                  # dev 模式通过代理转发 /api /swagger /healthz 到 :9527
    ├── eslint.config.js                # ESLint 9 flat config（@vue/eslint-config-typescript）
    ├── env.d.ts                        # Vite + Vue 类型声明
    ├── tsconfig.json                   # Project References 入口
    ├── tsconfig.app.json               # 应用 TS 配置
    ├── tsconfig.node.json              # Vite / ESLint 配置
    ├── .editorconfig
    ├── .prettierrc.json
    ├── public/                         # 静态资源（不经 Vite 处理）
    ├── index.html
    ├── dist/                           # 构建产物（.gitkeep 占位让 go:embed 能编译）
    └── src/
        ├── main.ts
        ├── App.vue                     # 整体布局（顶部导航 + router-view）
        ├── assets/
        │   └── theme.css               # 主题变量 / 通用控件样式
        ├── api/                        # axios 客户端 + 4 个领域模块
        │   ├── client.ts               # 拦截器解构 {code, message, data}（API_BASE 走相对路径）
        │   ├── request.ts
        │   ├── yaml.ts
        │   ├── finger.ts
        │   ├── library.ts
        │   └── index.ts
        ├── router/                     # Vue Router
        │   └── index.ts
        ├── stores/                     # Pinia 状态
        │   └── shared.ts
        ├── types/
        │   └── api.ts                  # 与 Go internal/model 对齐的 TS 类型
        ├── composables/                # Composition functions
        │   ├── monaco.ts               # Monaco worker / CEL Monarch + HTTP Shiki TextMate / 自动补全
        │   ├── httpLanguage.ts         # HTTP 报文嗅探（请求/响应整体走 http；body 单独走 json/html/xml）
        │   ├── fingerForm.ts           # 指纹表单 ↔ YAML 双向转换
        │   ├── fingerHints.ts          # CEL 函数 / set 变量 / 数据包模板提示
        │   ├── useTheme.ts             # 暗色/亮色主题切换（localStorage + 系统偏好 + Monaco 同步）
        │   └── useHorizontalSplit.ts   # 通用水平分隔条 composable
        ├── components/                 # 通用组件
        │   ├── MonacoYamlEditor.vue    # Monaco 编辑器统一封装（v-model + http/yaml/cel 共用主题）
        │   ├── ResponseView.vue        # 响应详情（raw/body/headers/request/certs 多 tab；body 支持 UTF-8/Hex/Base64 切换）
        │   ├── FingerFormEditor.vue    # 指纹规则可视化表单 + CEL 实时 lint
        │   ├── CollapsiblePanel.vue    # 可折叠面板
        │   ├── HintChipList.vue        # 提示芯片列表
        │   ├── PacketDetailDialog.vue  # 请求/响应数据包浮层（Teleport + 蓝灰柔光蒙层，无黑色 backdrop）
        │   └── TargetConfigBar.vue     # 目标 / TLS / 代理 / 超时配置条
        └── views/                      # 页面级视图（与 router 路由对应）
            ├── RequestView.vue         # 请求测试（Raw 模式 textarea → Monaco http 高亮）
            ├── FingerView.vue          # 指纹编辑 + 运行 + CEL 调试
            └── LibraryView.vue         # 指纹库 CRUD（目录树结构展示）
```

> **完全隔离**：根目录的 `go build ./...` / `go vet ./...` 不会触碰 `cmd/gxx-ide/`，
> wails / gin / swag 等依赖只存在于子 module 的 `go.mod` 中。

---

## 四、HTTP API 概览

> 统一响应格式：

```json
{
  "code": 200,
  "message": "success",
  "data": { /* ... */ }
}
```

- `code == 200` 业务成功；
- `code == 400` 入参错误（YAML 解析失败 / 参数缺失等）；
- `code == 500` 服务端异常。

### 路由列表（详情见 `/swagger/index.html`）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/healthz` | 健康检查 |
| GET  | `/swagger/*any` | Swagger UI |
| POST | `/api/v1/request/send` | 发送 HTTP 请求并返回完整响应 |
| POST | `/api/v1/yaml/validate` | 校验 YAML 指纹并返回 outline |
| POST | `/api/v1/finger/run` | 逐 rule 运行指纹，返回 r0/r1 中间结果 + varMap |
| POST | `/api/v1/cel/evaluate` | 单独求值 CEL 表达式 |
| GET  | `/api/v1/library/default` | 默认指纹库路径 |
| GET  | `/api/v1/library/list` | 列出指纹库下全部 .yaml/.yml |
| GET  | `/api/v1/library/load` | 加载指定文件内容 |
| POST | `/api/v1/library/save` | 保存指纹（先校验合法性） |
| DELETE | `/api/v1/library/delete` | 删除指纹文件 |

### Swagger UI

启动 GUI 或后端后访问：

```
http://127.0.0.1:9527/swagger/index.html
```

---

## 五、运行 / 构建

> 环境依赖：Go 1.25.0+、Node.js 20.19+ 或 22.12+、npm 9+、Wails CLI v2.10+

> **PATH 说明**：`go install` 安装的 `wails` / `swag` 位于 `$(go env GOPATH)/bin`（默认 `~/go/bin`）。
> `make dev-gui` / `ide-dev.sh wails` 会自动检测并加入 PATH；若手动运行，请执行：
> `export PATH="$(go env GOPATH)/bin:$PATH"`

API 会话认证和独立浏览器开发配置见 [IDE 使用说明](cmd/gxx-ide/README.md#api-会话认证)。

### 安装依赖

```bash
# 一键安装 Go/npm 依赖 + 自动安装 wails/swag CLI
make gui-deps
```

### 生成 Swagger 文档

```bash
make swagger
# 等价于：cd cmd/gxx-ide && swag init -g main.go -o docs
```

### 开发模式（热重载）

```bash
# 推荐：浏览器开发（无需 wails，API + Vite 同时启动）
chmod +x ide-dev.sh
./ide-dev.sh deps
./ide-dev.sh all
# 浏览器访问 http://127.0.0.1:5173

# 桌面 GUI 热重载（需 wails CLI）
./ide-dev.sh wails
# 或
make dev-gui
```

### 单平台生产构建

```bash
make build-gui
# 或
./ide-dev.sh gui
./build.sh --gui
# 产物：cmd/gxx-ide/build/bin/gxx-ide
```

### 跨平台打包（macOS + Windows）

```bash
make package-gui
# 或
./ide-dev.sh package
./build.sh --gui-all
# 产物：build/gxx-ide_*.zip（与 gxx CLI 同目录）
```

### 与主项目一并发布

```bash
make release
# 或
./build.sh --all
# 产物：build/gxx_*.zip + build/gxx-ide_*.zip
# CI 无 wails/Node 时可：GXX_SKIP_IDE=1 ./build.sh --all
```

### 清理 IDE 产物

```bash
./ide-dev.sh clean
# 或
./build.sh --gui-clean
```

### 仅启动后端（无 GUI / 适合容器 / 集成测试场景）

```bash
cd cmd/gxx-ide && go run . -headless -port 9527
# 浏览器访问 http://127.0.0.1:9527/swagger/index.html
# 第三方 CI/CD 也可通过 GXX_IDE_PORT 环境变量覆盖端口
```

### 跨平台批量打包

GXX IDE 仅交付 **macOS（arm64 / amd64）+ Windows（amd64）** 三种平台的客户端：

```bash
# 调用独立打包配置程序，默认打包上述三个平台
make package-gui

# 自定义平台子集
cd cmd/gxx-ide && go run ./scripts/packager --platforms=darwin/arm64,windows/amd64
```

`scripts/packager` 关键行为：

- **默认输出到仓库根 `build/`**，与主项目 `build.sh` 的 `gxx_*.zip` 同目录；
- **zip 命名与 CLI 一致**：`gxx-ide_mac_arm64_1.2.0.zip`、`gxx-ide_win_x64_1.2.0.zip` 等；
- **版本号**默认读取 `wails.json` 的 `info.productVersion`；
- **`--clean` 只删 `build/gxx-ide_*.zip`**，不会误删 `gxx_*.zip`；
- **每个平台构建前清空 `cmd/gxx-ide/build/bin/`**，避免 `.app` bundle 污染下一平台；
- **跨编译时默认 `CGO_ENABLED=0`**（除非用户显式覆盖）。

打包产物示例（与 `gxx_mac_arm64_1.2.0.zip` 并列）：

```
build/
├── gxx_mac_arm64_1.2.0.zip          # CLI
├── gxx_mac_x64_1.2.0.zip
├── gxx-ide_mac_arm64_1.2.0.zip      # IDE（内含 gxx-ide.app）
├── gxx-ide_mac_x64_1.2.0.zip
└── gxx-ide_win_x64_1.2.0.zip        # IDE（内含 gxx-ide.exe）
```

---

## 六、与主仓库的关系

| 主项目 | GXX IDE |
|--------|---------|
| 根目录 `go.mod` | `cmd/gxx-ide/go.mod`（独立 module） |
| `go build ./...` 主二进制 | `wails build` 出 GUI 二进制 |
| `pkg/cel` / `pkg/finger` / `pkg/network` | 通过 `replace github.com/cyberspacesec/gxx => ../..` 复用 |
| `sdk.*` | **不依赖** SDK，避免引入 Engine 全局状态 |
| 主二进制体积 | 完全不受 GUI 影响 |

任何主项目发布流程都**不需要**修改：即使删除整个 `cmd/gxx-ide/` 目录，主二进制构建依旧正常。

---

## 七、关键设计

### 7.1 统一响应封装

`internal/response/response.go` 仅暴露以下 API：

```go
response.OK(c, data)
response.OKMessage(c, msg, data)
response.BadRequest(c, msg)
response.ServerError(c, msg)
response.FromError(c, err)        // 自动按 BadRequestError 接口决定 400/500
response.NewBadRequest("提示")     // service 层显式标记 400 错误
```

### 7.2 端口策略 / 前后端通信

后端默认监听 `127.0.0.1:9527`：

```bash
gxx-ide -port 9527               # 默认端口
GXX_IDE_PORT=9999 gxx-ide        # 通过环境变量覆盖
gxx-ide -port 0                  # 系统随机端口（开发 / 多实例场景）
```

通信路径：

- **dev**（`./ide-dev.sh all`）：Vite 在 5173 启动，通过 `vite.config.ts` 的 proxy
  把 `/api` `/swagger` `/healthz` 转发到独立 Gin server（默认 :9527）。
- **wails 生产模式**：`main.go` 把 `server.Handler()`（Gin engine）注入
  `assetserver.Options.Handler`，作为静态资源 fallback。webview 内任何 fetch 都走
  相对路径 → wails 内嵌 server 优先匹配 embed.FS 中的静态资源，未命中 fallback
  到 Gin engine 处理 API/Swagger。
- **第三方工具**：始终通过独立 Gin server 的 `127.0.0.1:<port>` 调用（仍可被
  curl / httpie / postman 等使用，Swagger 中 try-it-out 也指向该端口）。

> 由于前端 axios 与 App.vue 的 Swagger 链接均使用相对路径，
> 即便用 `-port 0` 让系统随机分配端口、或 9527 被占用，IDE GUI 仍能正常工作。

### 7.3 Monaco 自定义语言 / 自动补全 / 主题

`frontend/src/composables/monaco.ts` 一次性完成全部初始化（`initialized` 单例保护）：

- **CEL 语言**：Monarch tokenizer，关键字 / 操作符 / 字节字面量 `b"..."` 高亮；
- **HTTP 语言**：通过 `@shikijs/monaco` 集成 Shiki TextMate grammar（来自 VS Code REST Client 扩展），
  支持 body 内嵌 JSON / XML / HTML / ShellScript 子语言高亮；Shiki 加载失败时回退到 Monarch；
- **27 个 CEL 函数** + **27 个 `request.*` / `response.*` 字段** + `r0()`~`r9()` snippet 自动补全；
- **主题**：Shiki 内置 `github-light` / `github-dark` 主题，通过 `useTheme.ts` composable 与
  CSS `[data-theme="dark"]` 变量联动，localStorage 持久化 + 系统偏好自动检测。

`composables/httpLanguage.ts` 提供两类嗅探：

| 函数 | 适用 | 行为 |
|------|------|------|
| `pickHttpRawLanguage(raw)` | 整段原始报文 | 首行匹配 `HTTP/...` 或 `METHOD ... HTTP/...` → `'http'`，否则 fallback 到 body 嗅探 |
| `detectHttpBodyLanguage(raw)` | 仅 body | Content-Type / 起始字符 → `json` / `html` / `xml` / `plaintext` |
| `httpBodyWordWrap(raw, lang)` | 自动折行决策 | 单行压缩 HTML 关闭 wrap，其它默认 `on` |

`MonacoYamlEditor.vue` 把所有 Monaco 使用场景统一到一个组件（命名遗留），
通过 `language` prop（`yaml \| cel \| http \| json \| html \| xml \| plaintext`）切换。

**性能**：所有视图通过 `defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))` 引入，
Vite 把 Monaco 拆为独立 chunk（`monaco-*.js`，~3MB），仅在首次实例化 MonacoYamlEditor 时按需加载；
主入口 `index-*.js` 从 ~3MB 降到 ~112KB（gzip ~44KB），首屏可立刻交互。

### 7.4 取消机制 (AbortController)

`api/client.ts` 暴露 `RequestOptions { signal?: AbortSignal }`，由四个领域 API（request/finger/yaml/library）
透传给 axios。视图层在每次新请求开始前 `abort()` 旧 controller，避免：

- 用户快速连点「发送 / 运行 / 保存」时旧响应覆盖新结果；
- 表单 deep watch 触发的连环校验在键入过程中相互覆盖。

新增 `isCanceledError(err)` 辅助函数，调用方可在 catch 分支直接 `if (isCanceledError(err)) return` 忽略主动取消。

### 7.5 数据流与状态管理

| 层 | 职责 | 实现要点 |
|----|------|----------|
| **Pinia store `useSharedStore`** | 跨视图共享的目标 / TLS / 代理 / 超时 / 最后请求-响应缓存 | `updateTargetConfig` / `updateFromResponse` 两条受控 action |
| **`TargetConfigBar`** | 纯 v-model 受控组件，不直接读写 store | 仅监听 `props.modelValue → form` 与 `form → emit`，避免双向 watch 死锁 |
| **`RequestView` / `FingerView`** | 在自身 setup 中用 `computed<RunTargetConfig>({ get, set })` 桥接 store ↔ TargetConfigBar | store 作为单一数据源，视图不再各自保留 reactive 副本 |

### 7.4 逐 rule 中间结果

`finger_service.go` 不依赖 `sdk.Engine`，直接 import 主项目的 `pkg/cel` / `pkg/finger` / `pkg/network`，
逐 rule 评估并返回每条 rule 的请求、响应、CEL 结果、错误，便于前端 r0/r1 面板展示。

---

## 八、Roadmap

- [x] HTTP raw 报文语法高亮（请求 / 响应 / RequestView Raw 模式）
- [x] 请求详情对话框采用 Teleport + 轻量蒙层（去除原 `<dialog>` 黑色 backdrop）
- [x] 规则面板折叠状态按 `rule.key` 追踪（删除规则后状态不再错位）
- [x] **请求 / 校验 / 运行调用支持 `AbortController`**，新请求 abort 旧请求避免响应竞态
- [x] **Monaco 懒加载**：`defineAsyncComponent`，初始 JS chunk 从 ~3MB 降到 ~112KB
- [x] **TargetConfigBar 单向数据流**：移除 store→form 反向 watch；父组件用 `computed<RunTargetConfig>` 与 store 同步
- [x] **RequestView 复用 TargetConfigBar**：删除重复目标 / TLS / 代理 / 超时表单
- [x] **可变列表 stable key**：setVars / payloads / headers / matchers 通过 WeakMap uid 提供稳定 key
- [x] **PacketDetailDialog 焦点管理**：打开自动 focus 关闭按钮，关闭恢复触发元素焦点，Esc 关闭
- [x] **CEL 表达式 lint**：高级模式下实时调用 `/api/v1/cel/evaluate` 校验语法，inline 显示 ✓/✗
- [x] **response.body 多视图**：UTF-8 / Hex（hex dump 含偏移 + ASCII 预览）/ Base64 三种模式切换
- [x] **指纹库目录树**：按 `relPath` 构建树形结构，目录可展开/折叠，文件缩进分层
- [x] **暗色主题 + Monaco 同步**：`[data-theme="dark"]` CSS 变量 + `gxx-dark` Monaco 主题，`useTheme` composable + localStorage 持久化

---

## 九、相关链接

- 主项目 README: [README.md](README.md)
- GXX SDK 文档: [sdk/sdk.md](sdk/sdk.md)
- 指纹规则手册: [docs/指纹规则格式说明.md](docs/指纹规则格式说明.md)
- 指纹开发速查: [docs/指纹开发快速参考.md](docs/指纹开发快速参考.md)
