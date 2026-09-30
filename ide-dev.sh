#!/bin/bash
# GXX IDE 本地开发 / 构建脚本
# 用法: ./ide-dev.sh [模式]
#
# 模式:
#   deps     安装前后端依赖
#   api      仅启动 Gin API（headless，默认 :9527）
#   web      仅启动 Vite 前端（代理到 API）
#   all      同时启动 API + Vite（浏览器开发，无需 wails）
#   wails    使用 wails dev 启动完整桌面 GUI
#   lint     运行 ESLint + TypeScript 类型检查
#   build    构建前端 + 编译 Go 后端（开发验证，非 wails 产物）
#   gui      单平台 wails build → build/gxx-ide_*.zip（与 gxx CLI 同目录）
#   package  跨平台打包 → build/gxx-ide_*.zip（与 gxx CLI 同目录）
#   clean    清理 IDE 构建产物（保留 build/gxx_*.zip）
#   help     显示帮助

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
IDE_DIR="$ROOT_DIR/cmd/gxx-ide"
FRONTEND_DIR="$IDE_DIR/frontend"
BUILD_DIR="$ROOT_DIR/build"
BUILD_SH="$ROOT_DIR/build.sh"
API_PORT="${GXX_IDE_API_PORT:-9527}"
API_PID=""

export GOSUMDB="${GOSUMDB:-sum.golang.google.cn}"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

GOPATH_BIN="$(go env GOPATH)/bin"
export PATH="$GOPATH_BIN:$PATH"
WAILS="$GOPATH_BIN/wails"
WAILS_GO="$IDE_DIR/scripts/wails-go"

show_help() {
  cat <<EOF
GXX IDE 开发脚本

用法: $0 [模式]

开发模式:
  deps     安装 Go module 与 npm 依赖
  api      仅启动 Gin API（--headless，端口 ${API_PORT}）
  web      仅启动 Vite 前端（http://127.0.0.1:5173，代理 /api 到 :${API_PORT}）
  all      同时启动 API + Vite（推荐浏览器开发）
  wails    wails dev 热重载桌面 GUI（需安装 wails CLI）

构建 / 打包:
  build    前端 build + Go 编译验证（不含 wails 桌面产物）
  gui      单平台 wails build → build/gxx-ide_*.zip（与 gxx CLI 同目录）
  package  跨平台打包 IDE → ${BUILD_DIR}/gxx-ide_*.zip（调用 build.sh --gui-all）
  clean    清理 IDE 产物（build/gxx-ide_*.zip + cmd/gxx-ide/build/）

  lint     ESLint + vue-tsc 类型检查
  help     显示本帮助

环境变量:
  GXX_IDE_API_PORT   API 监听端口（默认 9527）

示例:
  $0 deps && $0 all
  $0 wails
  $0 package          # 产物与 make release / build.sh --all 中的 IDE zip 相同目录
EOF
}

cleanup() {
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    echo "停止 API 进程 (pid=$API_PID)..."
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

require_cmd() {
  if ! command -v "$1" &>/dev/null; then
    echo "错误: 未找到 $1，请先安装。" >&2
    exit 1
  fi
}

ensure_build_sh() {
  if [[ ! -x "$BUILD_SH" ]]; then
    chmod +x "$BUILD_SH"
  fi
}

ensure_wails() {
  if [[ ! -x "$WAILS" ]]; then
    echo "==> 安装 wails CLI 到 $GOPATH_BIN..."
    go install github.com/wailsapp/wails/v2/cmd/wails@latest
  fi
  if [[ ! -x "$WAILS" ]]; then
    echo "错误: wails 安装失败，请手动执行：" >&2
    echo "  go install github.com/wailsapp/wails/v2/cmd/wails@latest" >&2
    echo "并确保 \$PATH 包含: $GOPATH_BIN" >&2
    exit 1
  fi
}

install_deps() {
  require_cmd go
  require_cmd npm
  echo "==> 安装 Go 依赖..."
  (cd "$IDE_DIR" && go mod tidy)
  echo "==> 安装前端依赖..."
  (cd "$FRONTEND_DIR" && npm install)
  echo "依赖安装完成"
}

kill_existing_api() {
  local pids
  pids=$(lsof -ti :"$API_PORT" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    echo "==> 检测到端口 ${API_PORT} 已被占用，正在终止旧进程..."
    echo "$pids" | xargs kill -9 2>/dev/null || true
    sleep 1
  fi
}

start_api() {
  require_cmd go
  kill_existing_api
  echo "==> 启动 Gin API（headless，端口 ${API_PORT}）..."
  echo "    Swagger: http://127.0.0.1:${API_PORT}/swagger/index.html"
  (cd "$IDE_DIR" && go run . --headless --port="${API_PORT}")
}

wait_for_api() {
  local port="${1:-9527}"
  local max_wait="${2:-90}"
  local url="http://127.0.0.1:${port}/healthz"
  echo "==> 等待 API 就绪: ${url}"
  for ((i = 1; i <= max_wait; i++)); do
    if curl -sf "$url" >/dev/null 2>&1; then
      echo "    API 已就绪 (${i}s)"
      return 0
    fi
    if [[ -n "${API_PID:-}" ]] && ! kill -0 "$API_PID" 2>/dev/null; then
      echo "错误: API 进程已退出，请检查上方 go run 日志" >&2
      exit 1
    fi
    sleep 1
  done
  echo "错误: 等待 API 超时 (${max_wait}s)，请确认端口 ${port} 未被占用" >&2
  exit 1
}

start_api_bg() {
  require_cmd go
  require_cmd curl
  require_cmd node
  if [[ -z "${GXX_IDE_TOKEN:-}" ]]; then
    GXX_IDE_TOKEN="$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")"
    export GXX_IDE_TOKEN
  fi
  export VITE_GXX_IDE_TOKEN="$GXX_IDE_TOKEN"
  kill_existing_api
  echo "==> 后台启动 Gin API（端口 ${API_PORT}）..."
  (cd "$IDE_DIR" && go run . --headless --port="${API_PORT}") &
  API_PID=$!
  wait_for_api "$API_PORT"
  echo "    API 进程 pid=$API_PID"
  echo "    Swagger: http://127.0.0.1:${API_PORT}/swagger/index.html"
}

start_web() {
  require_cmd npm
  echo "==> 启动 Vite 前端..."
  echo "    浏览器: http://127.0.0.1:5173"
  echo "    API 代理: http://127.0.0.1:${API_PORT}"
  (cd "$FRONTEND_DIR" && GXX_IDE_API_PORT="$API_PORT" npm run dev)
}

start_wails() {
  require_cmd go
  ensure_wails
  echo "==> 启动 wails dev（$WAILS）..."
  (cd "$IDE_DIR" && "$WAILS" dev)
}

run_lint() {
  require_cmd npm
  (cd "$FRONTEND_DIR" && npm run lint)
  (cd "$FRONTEND_DIR" && npm run type-check)
  echo "Lint 与类型检查通过"
}

run_build() {
  require_cmd npm
  require_cmd go
  (cd "$FRONTEND_DIR" && npm run build)
  (cd "$IDE_DIR" && go build -o /dev/null .)
  echo "前端与后端构建验证通过"
}

run_gui() {
  ensure_build_sh
  echo "==> 单平台 GXX IDE 构建 → ${BUILD_DIR}/gxx-ide_*.zip"
  (cd "$ROOT_DIR" && "$BUILD_SH" --gui)
}

run_package() {
  ensure_build_sh
  echo "==> 跨平台打包 GXX IDE → ${BUILD_DIR}/gxx-ide_*.zip"
  (cd "$ROOT_DIR" && "$BUILD_SH" --gui-all)
}

run_clean() {
  ensure_build_sh
  (cd "$ROOT_DIR" && "$BUILD_SH" --gui-clean)
}

MODE="${1:-help}"

case "$MODE" in
  deps)
    install_deps
    ;;
  api)
    start_api
    ;;
  web)
    start_web
    ;;
  all)
    install_deps
    start_api_bg
    start_web
    ;;
  wails)
    start_wails
    ;;
  lint)
    run_lint
    ;;
  build)
    run_build
    ;;
  gui)
    run_gui
    ;;
  package)
    run_package
    ;;
  clean)
    run_clean
    ;;
  help|-h|--help)
    show_help
    ;;
  *)
    echo "未知模式: $MODE" >&2
    show_help
    exit 1
    ;;
esac
