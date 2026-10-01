.PHONY: build build-embed clean run test build-gui dev-gui gui-deps gui-clean swagger package-gui ensure-wails ensure-swag

# 默认目标：全量发布包（CLI 全平台默认嵌入指纹库 + GXX IDE 跨平台 zip → build/）
all: release

# 构建项目（不嵌入指纹库）
build:
	@echo "构建项目（不嵌入指纹库）..."
	@BUILD_DATE=$$(date +"%Y-%m-%d") && \
	GXX_VERSION="1.2.0" && \
	GXX_AUTHOR="zhizhuo" && \
	go build -ldflags "-X 'github.com/cyberspacesec/gxx/cmd/cli.defaultVersion=$$GXX_VERSION' -X 'github.com/cyberspacesec/gxx/cmd/cli.defaultAuthor=$$GXX_AUTHOR' -X 'github.com/cyberspacesec/gxx/cmd/cli.defaultBuildDate=$$BUILD_DATE'" -o gxx ./cmd/main.go
	@echo "构建完成：使用磁盘 fingerYaml/ 目录（需与二进制同目录或工作目录下）"

# 构建项目（嵌入指纹库）
build-embed:
	@echo "构建项目（嵌入指纹库）..."
	@BUILD_DATE=$$(date +"%Y-%m-%d") && \
	GXX_VERSION="1.2.0" && \
	GXX_AUTHOR="zhizhuo" && \
	go build -tags embed -ldflags "-X 'github.com/cyberspacesec/gxx/cmd/cli.defaultVersion=$$GXX_VERSION' -X 'github.com/cyberspacesec/gxx/cmd/cli.defaultAuthor=$$GXX_AUTHOR' -X 'github.com/cyberspacesec/gxx/cmd/cli.defaultBuildDate=$$BUILD_DATE'" -o gxx ./cmd/main.go
	@echo "构建完成：指纹库已嵌入二进制（单文件部署）"

# 使用build.sh脚本构建发布包（默认嵌入指纹库）
release:
	@echo "构建发布包（默认嵌入指纹库）..."
	@chmod +x build.sh
	@./build.sh --all

# 使用build.sh脚本构建发布包（嵌入指纹库）
release-embed:
	@echo "构建发布包（嵌入指纹库）..."
	@chmod +x build.sh
	@./build.sh --embed --all

# 清理构建产物
clean:
	@echo "清理构建产物..."
	@rm -f gxx
	@rm -rf dist
	@echo "清理完成"

# 运行项目
run:
	@echo "运行项目..."
	@go run ./cmd/main.go

# 测试项目
test:
	@echo "运行测试..."
	@go test ./...

# --------------------------- GXX IDE (GUI) ---------------------------
# GUI 是独立 Go module（cmd/gxx-ide/），构建依赖 wails CLI + Node.js + npm。
# wails / swag 默认安装到 $(go env GOPATH)/bin，Make 会自动加入 PATH。

GOPATH_BIN := $(shell go env GOPATH)/bin
WAILS      := $(GOPATH_BIN)/wails
SWAG       := $(GOPATH_BIN)/swag
WAILS_GO   := $(CURDIR)/cmd/gxx-ide/scripts/wails-go
GUI_ENV    := GOSUMDB=sum.golang.google.cn GOPROXY=https://goproxy.cn,direct

# 确保 wails CLI 可用（未安装则自动 go install）
ensure-wails:
	@if [ ! -x "$(WAILS)" ]; then \
		echo "==> 安装 wails CLI 到 $(GOPATH_BIN)..."; \
		$(GUI_ENV) go install github.com/wailsapp/wails/v2/cmd/wails@latest; \
	fi

# 确保 swag CLI 可用
ensure-swag:
	@if [ ! -x "$(SWAG)" ]; then \
		echo "==> 安装 swag CLI 到 $(GOPATH_BIN)..."; \
		$(GUI_ENV) go install github.com/swaggo/swag/cmd/swag@latest; \
	fi

# 安装 GUI 前后端依赖 + CLI 工具
gui-deps: ensure-wails ensure-swag
	@echo "安装 GUI Go 依赖..."
	@cd cmd/gxx-ide && go mod tidy
	@echo "安装 GUI 前端依赖..."
	@cd cmd/gxx-ide/frontend && npm install
	@echo "依赖安装完成（wails: $(WAILS)）"

# 生成 Swagger OpenAPI 文档
swagger: ensure-swag
	@echo "生成 Swagger 文档..."
	@cd cmd/gxx-ide && PATH="$(GOPATH_BIN):$$PATH" "$(SWAG)" init -g main.go -o docs --parseDependency --parseInternal
	@echo "Swagger 文档已生成：cmd/gxx-ide/docs/"

# 开发模式启动 GUI（热重载）
dev-gui: ensure-wails
	@echo "启动 GUI 开发模式..."
	@cd cmd/gxx-ide && PATH="$(GOPATH_BIN):$$PATH" "$(WAILS)" dev

# 构建 GUI 二进制（当前平台 → build/gxx-ide_*.zip）
build-gui: ensure-wails
	@echo "构建 GXX IDE（当前平台 → build/）..."
	@./build.sh --gui

# 跨平台批量打包（调用独立 packager）：默认打包 macOS arm64/amd64 + Windows amd64
package-gui: ensure-wails
	@echo "跨平台打包 GXX IDE（macOS + Windows）..."
	@mkdir -p build
	@cd cmd/gxx-ide && PATH="$(GOPATH_BIN):$$PATH" go run ./scripts/packager \
		--output=../../build \
		--version=1.2.0 \
		--name=gxx-ide
	@echo "打包完成：build/gxx-ide_*.zip（与 gxx CLI 同目录）"

# 清理 GUI 构建产物
gui-clean:
	@cd cmd/gxx-ide && rm -rf build/bin frontend/dist frontend/node_modules docs/swagger.json docs/swagger.yaml
	@rm -f build/gxx-ide_*.zip
	@echo "GUI 构建产物已清理（含 build/gxx-ide_*.zip）"

# 帮助信息
help:
	@echo "可用的命令:"
	@echo "  make all           - 同 make release（CLI 全平台 + GXX IDE → build/）"
	@echo "  make build         - 构建当前平台本地二进制（不打包）"
	@echo "  make build-embed   - 构建项目（嵌入指纹库）"
	@echo "  make release       - 构建发布包（CLI 全平台默认嵌入指纹库 + GXX IDE 跨平台 zip → build/）"
	@echo "  make release-embed - 构建发布包（嵌入指纹库 + GXX IDE）"
	@echo "  make clean         - 清理构建产物"
	@echo "  make run           - 运行项目"
	@echo "  make test          - 运行测试"
	@echo ""
	@echo "GUI 相关（cmd/gxx-ide/ 独立 module）："
	@echo "  make gui-deps      - 安装 GUI Go 依赖与前端 npm 依赖"
	@echo "  make swagger       - 生成 Swagger OpenAPI 文档"
	@echo "  make dev-gui       - wails dev 热重载启动 GUI"
	@echo "  make build-gui     - 单平台构建 GUI → build/gxx-ide_*.zip"
	@echo "  make package-gui   - 跨平台批量打包（产物：build/gxx-ide_*.zip）"
	@echo "  make gui-clean     - 清理 GUI 构建产物"
	@echo ""
	@echo "  make help          - 显示帮助信息"
