#!/bin/bash

# 设置应用名称和版本号
APP_NAME="gxx"
IDE_APP_NAME="gxx-ide"
VERSION="${GXX_VERSION:-2.0.0}"
AUTHOR="zhizhuo"
# 添加构建时间
BUILD_DATE="${GXX_BUILD_DATE:-$(date -u +"%Y-%m-%d")}"

# 创建构建目录
BUILD_DIR="build"
mkdir -p $BUILD_DIR

# 显示帮助信息
show_help() {
    echo "GXX 构建脚本"
    echo "用法: $0 [选项]"
    echo "选项:"
    echo "  -h, --help     显示帮助信息"
    echo "  -v, --version  显示版本信息"
    echo "  -c, --clean    清理构建目录"
    echo "  -a, --all      构建所有平台 CLI（默认嵌入指纹库）+ 跨平台打包 GXX IDE → ${BUILD_DIR}/"
    echo "  -d, --debug    启用调试模式"
    echo "  -e, --embed    嵌入指纹库"
    echo "  -g, --gui      构建 GXX IDE（当前平台，需 wails CLI）"
    echo "  -G, --gui-all  跨平台打包 GXX IDE → ${BUILD_DIR}/${IDE_APP_NAME}_*.zip"
    echo "  --gui-clean    清理 GXX IDE 构建产物（保留 ${BUILD_DIR}/gxx_*.zip）"
    echo "IDE 开发与打包:"
    echo "  ./ide-dev.sh all       浏览器开发（API + Vite）"
    echo "  ./ide-dev.sh wails     桌面 GUI 热重载"
    echo "  ./ide-dev.sh gui       单平台 wails build"
    echo "  ./ide-dev.sh package   跨平台打包 IDE → ${BUILD_DIR}/${IDE_APP_NAME}_*.zip"
    echo "  ./ide-dev.sh clean     清理 IDE 构建产物"
    echo ""
    echo "环境变量:"
    echo "  GXX_NO_EMBED=1        --all 时不嵌入指纹库（需随包提供 fingerYaml/）"
    echo "  GXX_SKIP_IDE=1         强制跳过 IDE 打包"
    echo "  GXX_SKIP_UPX=1         发布原始可执行文件，跳过 UPX 压缩"
    echo "  GXX_SKIP_IDE_MAC=1     --all 时仅跳过 GXX IDE macOS 目标"
    echo "  GXX_IDE_PLATFORMS      覆盖 IDE 目标平台（如 darwin/arm64,windows/amd64）"
    echo "支持的平台和架构:"
    echo "  - darwin/amd64"
    echo "  - darwin/arm64"
    echo "  - linux/amd64"
    echo "  - linux/arm64"
    echo "  - windows/amd64"
    echo "  - windows/arm64"
}

# 显示版本信息
show_version() {
    echo "GXX 版本: $VERSION"
}

# 清理构建目录
clean_build() {
    echo "清理构建目录..."
    rm -rf $BUILD_DIR
    echo "清理完成"
}

# 构建函数
build() {
    GOOS=$1
    GOARCH=$2
    DEBUG=$3
    EMBED=$4

    # 根据平台和架构设置输出名称中的平台和架构部分
    case $GOOS in
        windows)
            PLATFORM="win"
            ;;
        darwin)
            PLATFORM="mac"
            ;;
        linux)
            PLATFORM="linux"
            ;;
        *)
            echo "未知的平台: $GOOS"
            exit 1
    esac

    case $GOARCH in
        amd64)
            ARCH="x64"
            ;;
        386)
            ARCH="x86"
            ;;
        arm64)
            ARCH="arm64"
            ;;
        arm)
            ARCH="arm"
            ;;
        *)
            echo "未知的架构: $GOARCH"
            exit 1
    esac

    OUTPUT_NAME="${APP_NAME}"
    OUTPUT_ZIP_NAME="${APP_NAME}_${PLATFORM}_${ARCH}_${VERSION}"

    echo "正在为 ${PLATFORM}/${ARCH} 构建..."

    # 设置输出文件名
    if [ "$GOOS" == "windows" ]; then
        OUTPUT_FILE="$BUILD_DIR/$OUTPUT_NAME.exe"
    else
        OUTPUT_FILE="$BUILD_DIR/$OUTPUT_NAME"
    fi

    # 构建标志
    LDFLAGS="-w -s"
    if [ "$DEBUG" == "true" ]; then
        LDFLAGS="-w"
    fi

    # 添加版本和作者信息到 ldflags
    LDFLAGS="$LDFLAGS -X 'github.com/cyberspacesec/gxx/v2/cmd/cli.defaultVersion=$VERSION' -X 'github.com/cyberspacesec/gxx/v2/cmd/cli.defaultAuthor=$AUTHOR' -X 'github.com/cyberspacesec/gxx/v2/cmd/cli.defaultBuildDate=$BUILD_DATE'"

    # 构建参数
    local build_args=(-ldflags "$LDFLAGS" -o "$OUTPUT_FILE")
    if [ "$EMBED" == "true" ]; then
        build_args+=(-tags embed)
    fi
    build_args+=(./cmd/main.go)

    # 执行构建
    if ! env GOOS="$GOOS" GOARCH="$GOARCH" go build "${build_args[@]}"; then
        echo "${PLATFORM}/${ARCH} 的构建失败。"
        exit 1
    fi

    # 使用 UPX 压缩可执行文件（如果安装了 upx）
    if [[ "${GXX_SKIP_UPX:-}" == "1" ]]; then
        echo "跳过 UPX 压缩（GXX_SKIP_UPX=1）。"
    elif command -v upx &> /dev/null; then
        if [ "$GOOS" != "windows" ] || [ "$GOARCH" != "arm64" ]; then
            if [ "$GOOS" != "darwin" ]; then
                echo "正在使用 UPX 压缩 ${OUTPUT_FILE}..."
                if ! upx $OUTPUT_FILE; then
                    echo "${PLATFORM}/${ARCH} 的 UPX 压缩失败。"
                    exit 1
                fi
            else
                echo "跳过对 macOS 的 UPX 压缩。"
            fi
        else
            echo "跳过对 Windows ARM64 的 UPX 压缩。"
        fi
    else
        echo "未找到 UPX，跳过压缩步骤。"
    fi

    # 压缩成 zip 文件
    ZIP_FILE="$BUILD_DIR/$OUTPUT_ZIP_NAME.zip"
    if ! zip -j "$ZIP_FILE" "$OUTPUT_FILE"; then
        echo "${PLATFORM}/${ARCH} 的 ZIP 打包失败。"
        exit 1
    fi

    rm "$OUTPUT_FILE"
    echo "${PLATFORM}/${ARCH} 的构建和打包完成：${ZIP_FILE}"
}

# 确保 wails CLI 可用（失败时返回 1，由调用方决定是否 exit）
ensure_wails() {
    GOPATH_BIN="$(go env GOPATH)/bin"
    WAILS="$GOPATH_BIN/wails"
    if [ ! -x "$WAILS" ]; then
        echo "==> 安装 wails CLI 到 $GOPATH_BIN..."
        GOSUMDB="${GOSUMDB:-sum.golang.google.cn}" GOPROXY="${GOPROXY:-https://mirrors.aliyun.com/goproxy/,https://goproxy.cn}" \
            go install "github.com/wailsapp/wails/v2/cmd/wails@${WAILS_VERSION:-latest}"
    fi
    if [ ! -x "$WAILS" ]; then
        echo "wails 安装失败，请确保 \$PATH 包含: $GOPATH_BIN"
        return 1
    fi
    export GOPATH_BIN WAILS
    return 0
}

# 清理 GXX IDE 构建产物（不删除整个 build/，避免误删 gxx_*.zip）
clean_gui() {
    echo "清理 GXX IDE 构建产物..."
    rm -rf cmd/gxx-ide/build cmd/gxx-ide/frontend/dist
    rm -f "$BUILD_DIR/${IDE_APP_NAME}_"*.zip
    echo "GXX IDE 清理完成（已删除 $BUILD_DIR/${IDE_APP_NAME}_*.zip）"
}

# 构建 GXX IDE（当前平台 → build/gxx-ide_{platform}_{arch}_{version}.zip，与 gxx CLI 同目录）
build_gui() {
    echo "构建 GXX IDE（当前平台 → ${BUILD_DIR}/）..."
    ensure_wails || exit 1
    if ! command -v zip &> /dev/null; then
        echo "未找到 zip 命令，请先安装 zip 后再打包 IDE"
        exit 1
    fi
    mkdir -p "$BUILD_DIR"
    local plat
    plat="$(go env GOOS)/$(go env GOARCH)"
    if ! (cd cmd/gxx-ide && PATH="$GOPATH_BIN:$PATH" go run ./scripts/packager \
        --output="../../${BUILD_DIR}" \
        --version="$VERSION" \
        --name="$IDE_APP_NAME" \
        --platforms="$plat" \
        --clean=false); then
        exit 1
    fi
    echo "GXX IDE 构建完成：${BUILD_DIR}/${IDE_APP_NAME}_*.zip（Wails 中间产物在 cmd/gxx-ide/build/bin/）"
}

# 检测 --all 场景下是否具备 IDE 打包前置条件
ide_pack_prereqs_ok() {
    local missing=()
    [[ -d "cmd/gxx-ide" ]] || missing+=("cmd/gxx-ide")
    [[ -f "cmd/gxx-ide/wails.json" ]] || missing+=("wails.json")
    command -v zip &>/dev/null || missing+=("zip")
    command -v npm &>/dev/null || missing+=("npm")
    if ((${#missing[@]} > 0)); then
        echo "${missing[*]}"
        return 1
    fi
    return 0
}

in_ci() {
    [[ "${CI:-}" == "true" ]]
}

filter_mac_platforms() {
    local raw="$1"
    local out=""
    local item
    local old_ifs="$IFS"
    IFS=","
    for item in $raw; do
        if [[ "$item" == darwin/* ]]; then
            continue
        fi
        if [[ -z "$out" ]]; then
            out="$item"
        else
            out="${out},${item}"
        fi
    done
    IFS="$old_ifs"
    echo "$out"
}

# --all 时按需打包 IDE：缺依赖或 CI 失败时不阻断 CLI 构建
build_gui_all_if_ready() {
    if [[ "${GXX_SKIP_IDE:-}" == "1" ]]; then
        echo "跳过 GXX IDE 打包（GXX_SKIP_IDE=1）"
        return 0
    fi

    local missing
    if ! missing=$(ide_pack_prereqs_ok); then
        echo "跳过 GXX IDE 打包（缺少: ${missing}）"
        return 0
    fi

    echo ""
    echo "========== GXX IDE 跨平台打包 =========="
    if build_gui_all; then
        return 0
    fi

    if in_ci && [[ "${GXX_FORCE_IDE:-}" != "1" ]]; then
        echo "警告: GXX IDE 打包失败，CI 构建继续（CLI zip 已生成；设置 GXX_FORCE_IDE=1 可在失败时阻断）"
        return 0
    fi

    echo "GXX IDE 打包失败"
    exit 1
}
# 跨平台打包 GXX IDE → build/gxx-ide_{platform}_{arch}_{version}.zip
build_gui_all() {
    echo "跨平台打包 GXX IDE（macOS + Windows）..."
    ensure_wails || return 1
    if ! command -v zip &> /dev/null; then
        echo "未找到 zip 命令，请先安装 zip 后再打包 IDE"
        return 1
    fi
    mkdir -p "$BUILD_DIR"
    PACKAGER_OUTPUT="../../${BUILD_DIR}"
    local platforms="${GXX_IDE_PLATFORMS:-darwin/arm64,darwin/amd64,windows/amd64}"
    if [[ "${GXX_SKIP_IDE_MAC:-${GXX_SKIP_MAC:-}}" == "1" ]]; then
        platforms="$(filter_mac_platforms "$platforms")"
        echo "跳过 GXX IDE macOS 平台（GXX_SKIP_IDE_MAC=1），当前 IDE 平台: ${platforms:-无}"
    fi
    if [[ -z "$platforms" ]]; then
        echo "未配置可构建的 GXX IDE 平台，跳过 IDE 打包。"
        return 0
    fi
    if ! (cd cmd/gxx-ide && PATH="$GOPATH_BIN:$PATH" go run ./scripts/packager \
        --output="$PACKAGER_OUTPUT" \
        --version="$VERSION" \
        --name="$IDE_APP_NAME" \
        --platforms="$platforms"); then
        return 1
    fi
    echo "GXX IDE 打包完成：${BUILD_DIR}/${IDE_APP_NAME}_*.zip（与 ${APP_NAME} CLI 同目录）"
    return 0
}

# 构建所有平台版本（CLI + GXX IDE）
build_all() {
    local DEBUG=$1
    local EMBED=$2

    # CLI：6 个平台/架构组合
    build "darwin" "amd64" "$DEBUG" "$EMBED"
    build "darwin" "arm64" "$DEBUG" "$EMBED"
    build "linux" "amd64" "$DEBUG" "$EMBED"
    build "linux" "arm64" "$DEBUG" "$EMBED"
    build "windows" "amd64" "$DEBUG" "$EMBED"
    build "windows" "arm64" "$DEBUG" "$EMBED"

    # IDE：macOS + Windows 跨平台 zip（与 CLI 同目录 build/）
    build_gui_all_if_ready
}

# 解析命令行参数
DEBUG=false
EMBED=false
CLEAN=false
ALL=false
GUI=false
GUI_ALL=false
GUI_CLEAN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            show_version
            exit 0
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -a|--all)
            ALL=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -e|--embed)
            EMBED=true
            shift
            ;;
        -g|--gui)
            GUI=true
            shift
            ;;
        -G|--gui-all)
            GUI_ALL=true
            shift
            ;;
        --gui-clean)
            GUI_CLEAN=true
            shift
            ;;
        *)
            echo "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

# 清理构建目录
if [ "$CLEAN" == "true" ]; then
    clean_build
    exit 0
fi

# 清理 GXX IDE 产物
if [ "$GUI_CLEAN" == "true" ]; then
    clean_gui
    exit 0
fi

# 构建 GXX IDE
if [ "$GUI_ALL" == "true" ]; then
    build_gui_all || exit 1
    exit 0
fi

if [ "$GUI" == "true" ]; then
    build_gui
    exit 0
fi

# 构建 GXX 主程序
if [ "$ALL" == "true" ]; then
    if [[ "$EMBED" != "true" && "${GXX_NO_EMBED:-}" != "1" ]]; then
        EMBED=true
        echo "--all 默认启用嵌入指纹库（设置 GXX_NO_EMBED=1 可关闭）"
    fi
    build_all "$DEBUG" "$EMBED"
else
    # 默认构建当前平台
    GOOS=$(go env GOOS)
    GOARCH=$(go env GOARCH)
    build "$GOOS" "$GOARCH" "$DEBUG" "$EMBED"
fi

echo "构建完成！"
