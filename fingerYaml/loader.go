//go:build !embed

// Package utils 提供指纹库的加载入口（默认构建从磁盘 fingerYaml/ 读取）。
package utils

import (
	"fmt"
	"os"
	"path/filepath"

	finger2 "github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/utils/common"
)

const defaultFingerDir = "fingerYaml"

// bundledFingerSubdirs 是随仓库分发的指纹库的已知顶层子目录。
// 用于判定某个 fingerYaml/ 是否为真正的内置规则库，而非恰好同名的无关目录。
var bundledFingerSubdirs = []string{"fingerprints", "fingers", "fofa", "jiajiu"}

// findFingerYamlDir 从工作目录逐级向上、并在可执行文件所在目录查找内置指纹库。
//
// 关键约束：只接受"看起来像内置库"的 fingerYaml/（包含其已知子目录中的至少两个）。
// 旧实现接受任意祖先目录中的 fingerYaml/，导致某个无关的、甚至只有一两条规则的
// 同名目录被静默采用，悄悄覆盖完整规则库（审查问题 S1）。结构校验既保留了从子目录
// 运行时能找到仓库根部规则库的便利，又避免了误用无关目录；自定义规则应通过
// PocFile/PocYaml 显式指定，而非依赖向上查找。
func findFingerYamlDir() (string, error) {
	seen := make(map[string]struct{})
	var roots []string
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; {
			roots = append(roots, dir)
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	for _, dir := range roots {
		candidate := filepath.Join(dir, defaultFingerDir)
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		if looksLikeBundledLibrary(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("未找到内置指纹库目录 %s（需包含 %v 等子目录）", defaultFingerDir, bundledFingerSubdirs)
}

// looksLikeBundledLibrary 判断目录是否为内置指纹库：存在且包含至少两个已知子目录。
func looksLikeBundledLibrary(dir string) bool {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return false
	}
	matched := 0
	for _, sub := range bundledFingerSubdirs {
		if st, err := os.Stat(filepath.Join(dir, sub)); err == nil && st.IsDir() {
			matched++
			if matched >= 2 {
				return true
			}
		}
	}
	return false
}

// GetFingerPath 返回磁盘指纹库目录。
func GetFingerPath() string {
	if dir, err := findFingerYamlDir(); err == nil {
		return dir + string(os.PathSeparator)
	}
	return defaultFingerDir + string(os.PathSeparator)
}

// GetFingerYaml 从 fingerYaml/ 目录加载全部指纹规则。
func GetFingerYaml() ([]*finger2.Finger, error) {
	root, err := findFingerYamlDir()
	if err != nil {
		return GetEmbeddedFingerYaml()
	}

	var allFinger []*finger2.Finger
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !common.IsYamlFile(path) {
			return nil
		}
		poc, err := finger2.Read(path)
		if err != nil {
			return fmt.Errorf("读取 %s 出错: %w", path, err)
		}
		if poc != nil {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			poc.Source.Path = filepath.ToSlash(relative)
			poc.Source.Builtin = matchesBuiltin(poc.Source.Path, poc.Source.SHA256)
			allFinger = append(allFinger, poc)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历指纹目录 %s 出错: %w", root, err)
	}
	return allFinger, nil
}
