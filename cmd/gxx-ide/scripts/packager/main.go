// Package main 是 GXX IDE 的跨平台打包配置程序。
//
// 用法（在 cmd/gxx-ide/ 目录下执行）：
//
//	go run ./scripts/packager
//	go run ./scripts/packager --platforms=darwin/arm64,windows/amd64
//	go run ./scripts/packager --output=../../build --version=2.0.0
//
// 默认把 zip 产物写入仓库根目录 build/，命名与主项目 build.sh 一致：
//
//	gxx-ide_mac_arm64_2.0.0.zip
//	gxx-ide_win_x64_2.0.0.zip
//
// 清理（--clean）仅删除 build/gxx-ide_*.zip，不会触碰 gxx_*.zip 等 CLI 产物。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var defaultPlatforms = strings.Join([]string{
	"darwin/arm64",
	"darwin/amd64",
	"windows/amd64",
}, ",")

func main() {
	platforms := flag.String("platforms", defaultPlatforms, "逗号分隔的目标平台列表，如 darwin/arm64,windows/amd64")
	output := flag.String("output", defaultBuildDir(), "打包产物目录（默认仓库根 build/，与 gxx CLI 相同）")
	version := flag.String("version", "", "写入 zip 文件名的版本号（默认读取 wails.json info.productVersion）")
	productName := flag.String("name", "gxx-ide", "产物前缀名称")
	cleanFlag := flag.Bool("clean", true, "构建前清理 output 目录下已有的 gxx-ide_*.zip")
	skipFrontend := flag.Bool("skip-frontend", false, "跳过前端构建")
	verbose := flag.Bool("verbose", true, "打印 wails 子进程实时输出")
	tags := flag.String("tags", "", "传递给 wails build 的 Go build tags（逗号分隔）")
	flag.Parse()

	if _, err := exec.LookPath("wails"); err != nil {
		if gopath := os.Getenv("GOPATH"); gopath != "" {
			candidate := filepath.Join(gopath, "bin", "wails")
			if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
				os.Setenv("PATH", filepath.Join(gopath, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			}
		}
	}
	if _, err := exec.LookPath("wails"); err != nil {
		exitErr("找不到 wails CLI，请先运行：go install github.com/wailsapp/wails/v2/cmd/wails@latest")
	}
	if _, err := exec.LookPath("zip"); err != nil {
		exitErr("找不到 zip 命令，macOS/Linux 请安装 zip 后再打包")
	}

	cwd, err := os.Getwd()
	if err != nil {
		exitErr(fmt.Sprintf("获取当前目录失败: %v", err))
	}
	if !fileExists(filepath.Join(cwd, "wails.json")) {
		exitErr(fmt.Sprintf("当前目录不是 wails 项目: %s（请在 cmd/gxx-ide/ 下运行）", cwd))
	}

	releaseRoot, err := resolveOutputDir(cwd, *output)
	if err != nil {
		exitErr(err.Error())
	}
	ver := strings.TrimSpace(*version)
	if ver == "" {
		ver = readProductVersion(cwd)
	}
	if ver == "" {
		ver = "dev"
	}

	if *cleanFlag {
		if err := cleanIDEReleases(releaseRoot, *productName); err != nil {
			exitErr(fmt.Sprintf("清理 %s 下 gxx-ide zip 失败: %v", releaseRoot, err))
		}
	}
	if err := os.MkdirAll(releaseRoot, 0o755); err != nil {
		exitErr(fmt.Sprintf("创建 %s 失败: %v", releaseRoot, err))
	}

	platformList := strings.Split(*platforms, ",")
	results := make([]platformResult, 0, len(platformList))

	for _, p := range platformList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		start := time.Now()
		res := buildPlatform(cwd, releaseRoot, p, *productName, ver, *tags, *skipFrontend, *verbose)
		res.Elapsed = time.Since(start)
		results = append(results, res)
	}

	printSummary(results, releaseRoot)
}

type platformResult struct {
	Platform string
	Output   string
	Err      error
	Elapsed  time.Duration
}

func defaultBuildDir() string {
	return "../../build"
}

func resolveOutputDir(cwd, output string) (string, error) {
	if output == "" {
		output = defaultBuildDir()
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(cwd, output)
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf("解析输出目录失败: %w", err)
	}
	return abs, nil
}

func readProductVersion(cwd string) string {
	data, err := os.ReadFile(filepath.Join(cwd, "wails.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Info struct {
			ProductVersion string `json:"productVersion"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Info.ProductVersion)
}

// cleanIDEReleases 只删除 gxx-ide_*.zip，避免误删同目录下的 gxx_*.zip。
func cleanIDEReleases(dir, productName string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	prefix := productName + "_"
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".zip") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildPlatform(cwd, releaseRoot, platform, productName, version, tags string, skipFrontend, verbose bool) platformResult {
	res := platformResult{Platform: platform}

	parts := strings.SplitN(platform, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		res.Err = fmt.Errorf("非法平台标识: %q（应为 goos/goarch）", platform)
		return res
	}
	goos, goarch := parts[0], parts[1]

	binDir := filepath.Join(cwd, "build", "bin")
	if err := os.RemoveAll(binDir); err != nil {
		res.Err = fmt.Errorf("清理 build/bin/ 失败: %w", err)
		return res
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		res.Err = fmt.Errorf("创建 build/bin/ 失败: %w", err)
		return res
	}

	outputName := productName
	if goos == "windows" {
		outputName = productName + ".exe"
	}

	args := []string{
		"build",
		"-platform", platform,
		"-clean",
		"-skipbindings",
		"-compiler", filepath.Join(cwd, "scripts", "wails-go"),
		"-o", outputName,
	}
	if skipFrontend {
		args = append(args, "-s")
	}
	if tags != "" {
		args = append(args, "-tags", tags)
	}

	cmd := exec.Command("wails", args...)
	cmd.Dir = cwd
	cmd.Env = buildEnv(goos, goarch)
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	fmt.Printf("==> [%s] wails %s\n", platform, strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		res.Err = err
		return res
	}
	fmt.Printf("    （中间产物，Wails 默认目录）→ %s\n", binDir)

	entries, err := os.ReadDir(binDir)
	if err != nil {
		res.Err = err
		return res
	}
	if len(entries) == 0 {
		res.Err = fmt.Errorf("wails 未生成任何产物（build/bin/ 为空）")
		return res
	}

	entries, err = normalizeReleaseEntries(binDir, goos, productName, entries)
	if err != nil {
		res.Err = err
		return res
	}

	zipName, err := zipBaseName(productName, goos, goarch, version)
	if err != nil {
		res.Err = err
		return res
	}
	zipPath := filepath.Join(releaseRoot, zipName+".zip")
	if err := archiveBinDir(binDir, zipPath, entries); err != nil {
		res.Err = fmt.Errorf("打包 %s 失败: %w", zipPath, err)
		return res
	}
	fmt.Printf("    （发布包，与 gxx CLI 同目录）→ %s\n", zipPath)
	res.Output = zipPath
	return res
}

// zipBaseName 与根目录 build.sh 的命名规则对齐：{name}_{platform}_{arch}_{version}
func zipBaseName(productName, goos, goarch, version string) (string, error) {
	platform, err := mapGOOS(goos)
	if err != nil {
		return "", err
	}
	arch, err := mapGOARCH(goarch)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%s_%s_%s", productName, platform, arch, version), nil
}

func mapGOOS(goos string) (string, error) {
	switch goos {
	case "windows":
		return "win", nil
	case "darwin":
		return "mac", nil
	case "linux":
		return "linux", nil
	default:
		return "", fmt.Errorf("未知的平台: %s", goos)
	}
}

func mapGOARCH(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x64", nil
	case "386":
		return "x86", nil
	case "arm64":
		return "arm64", nil
	case "arm":
		return "arm", nil
	default:
		return "", fmt.Errorf("未知的架构: %s", goarch)
	}
}

// normalizeReleaseEntries 确保 Windows 产物带 .exe，避免解压后无法双击运行。
func normalizeReleaseEntries(binDir, goos, productName string, entries []os.DirEntry) ([]os.DirEntry, error) {
	if goos != "windows" {
		return entries, nil
	}
	exeName := productName + ".exe"
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if ent.Name() == exeName {
			return entries, nil
		}
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if ent.Name() == productName {
			src := filepath.Join(binDir, ent.Name())
			dst := filepath.Join(binDir, exeName)
			if err := os.Rename(src, dst); err != nil {
				return nil, fmt.Errorf("重命名 Windows 可执行文件失败: %w", err)
			}
			return os.ReadDir(binDir)
		}
	}
	return entries, nil
}

func archiveBinDir(binDir, zipPath string, entries []os.DirEntry) error {
	_ = os.Remove(zipPath)

	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		names = append(names, ent.Name())
	}

	// 单文件（Windows .exe）走 -j，与 build.sh 一致；.app bundle 走 -ry。
	if len(names) == 1 {
		info, err := os.Stat(filepath.Join(binDir, names[0]))
		if err == nil && !info.IsDir() {
			cmd := exec.Command("zip", "-j", zipPath, names[0])
			cmd.Dir = binDir
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}

	args := append([]string{"-ry", zipPath}, names...)
	cmd := exec.Command("zip", args...)
	cmd.Dir = binDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func buildEnv(goos, goarch string) []string {
	env := os.Environ()
	upserts := map[string]string{
		"GOOS":   goos,
		"GOARCH": goarch,
	}
	if !hasEnv(env, "CGO_ENABLED") {
		hostOS, hostArch := runtimeOSArch()
		if goos != hostOS || goarch != hostArch {
			upserts["CGO_ENABLED"] = "0"
		}
	}
	return overrideEnv(env, upserts)
}

func runtimeOSArch() (string, string) {
	cmd := exec.Command("go", "env", "GOHOSTOS", "GOHOSTARCH")
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return "", ""
	}
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
}

func hasEnv(env []string, key string) bool {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return true
		}
	}
	return false
}

func overrideEnv(env []string, kv map[string]string) []string {
	seen := make(map[string]bool, len(kv))
	out := make([]string, 0, len(env)+len(kv))
	for _, e := range env {
		eq := strings.IndexByte(e, '=')
		if eq < 0 {
			out = append(out, e)
			continue
		}
		key := e[:eq]
		if v, ok := kv[key]; ok {
			out = append(out, key+"="+v)
			seen[key] = true
			continue
		}
		out = append(out, e)
	}
	for k, v := range kv {
		if !seen[k] {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func printSummary(results []platformResult, releaseRoot string) {
	fmt.Println()
	fmt.Println("打包结果汇总：")
	fmt.Println(strings.Repeat("-", 80))
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Printf("  ✗ %-22s  失败 (%v)  %s\n", r.Platform, r.Elapsed.Truncate(time.Millisecond), r.Err)
			continue
		}
		fmt.Printf("  ✓ %-22s  耗时 %s  产物: %s\n", r.Platform, r.Elapsed.Truncate(time.Millisecond), r.Output)
	}
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("输出目录: %s\n", releaseRoot)
	if failed > 0 {
		os.Exit(1)
	}
}

func exitErr(msg string) {
	fmt.Fprintln(os.Stderr, "[gxx-ide packager] "+msg)
	os.Exit(1)
}
