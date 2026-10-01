// Package utils 提供可在任意工作目录使用的内置指纹库。
package utils

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"

	finger2 "github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/utils/common"
)

func matchesBuiltin(path, digest string) bool {
	content, err := embeddedFingerFS.ReadFile(path)
	return err == nil && fmt.Sprintf("%x", sha256.Sum256(content)) == digest
}

//go:embed all:fingerprints all:fingers all:fofa all:jiajiu
var embeddedFingerFS embed.FS

// GetEmbeddedFingerYaml 从嵌入 FS 加载全部指纹规则。
func GetEmbeddedFingerYaml() ([]*finger2.Finger, error) {
	var allFinger []*finger2.Finger
	err := fs.WalkDir(embeddedFingerFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !common.IsYamlFile(d.Name()) {
			return nil
		}
		poc, err := finger2.Load(path, embeddedFingerFS)
		if err != nil {
			return fmt.Errorf("加载文件 %s 出错: %w", path, err)
		}
		if poc != nil {
			allFinger = append(allFinger, poc)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历嵌入指纹目录出错: %w", err)
	}
	return allFinger, nil
}
