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

// findFingerYamlDir 从当前工作目录向上查找仓库内的 fingerYaml/。
func findFingerYamlDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		candidate := filepath.Join(dir, defaultFingerDir)
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("指纹目录 %s 不可用（已从 %s 向上查找）", defaultFingerDir, wd)
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
