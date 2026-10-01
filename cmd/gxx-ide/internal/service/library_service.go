package service

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	fingerpkg "github.com/cyberspacesec/gxx/v2/pkg/finger"

	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/model"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/response"
)

// LibraryService 处理本地指纹库的 CRUD。
type LibraryService struct {
	mu    sync.RWMutex
	roots map[string]struct{}
}

// NewLibraryService 返回 LibraryService。
func NewLibraryService() *LibraryService { return &LibraryService{roots: make(map[string]struct{})} }

// DefaultDir 返回当前运行目录下的 fingerYaml/，不存在则自动创建。
//
// 查找顺序：当前工作目录 → 可执行文件所在目录 → 各目录的上两级。
// wails 打包后的 macOS .app 启动时 cwd 通常是 "/"，必须用 exe 所在目录回退。
func (s *LibraryService) DefaultDir() string {
	dir := s.findDefaultDir()
	_ = s.allowRoot(dir)
	return dir
}
func (s *LibraryService) findDefaultDir() string {
	cwd, _ := os.Getwd()
	exeDir := ""
	if exePath, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exePath)
	}

	roots := []string{cwd, exeDir}
	candidates := make([]string, 0, len(roots)*3)
	for _, root := range roots {
		if root == "" {
			continue
		}
		candidates = append(candidates,
			filepath.Join(root, fingerpkg.FingerFile),
			filepath.Join(root, "..", fingerpkg.FingerFile),
			filepath.Join(root, "..", "..", fingerpkg.FingerFile),
		)
	}

	for _, candidate := range candidates {
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() && containsYAML(candidate) {
			if abs, absErr := filepath.Abs(candidate); absErr == nil {
				return abs
			}
			return candidate
		}
	}
	for _, candidate := range candidates {
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			if abs, absErr := filepath.Abs(candidate); absErr == nil {
				return abs
			}
			return candidate
		}
	}

	// 优先在 cwd 创建（开发场景），cwd 不可写时回退到 exe 同级
	preferredRoot := cwd
	if preferredRoot == "" {
		preferredRoot = exeDir
	}
	dir := filepath.Join(preferredRoot, fingerpkg.FingerFile)
	if err := os.MkdirAll(dir, 0o755); err != nil && exeDir != "" && exeDir != preferredRoot {
		dir = filepath.Join(exeDir, fingerpkg.FingerFile)
		_ = os.MkdirAll(dir, 0o755)
	}
	return dir
}

func containsYAML(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if found {
			return filepath.SkipAll
		}
		if d.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
			found = true
		}
		return nil
	})
	return found
}

// List 列举 rootDir 下的全部 .yaml / .yml 文件并可选返回 outline。
func (s *LibraryService) List(rootDir string, includeOutline bool) ([]model.FingerFileMeta, error) {
	if strings.TrimSpace(rootDir) == "" {
		rootDir = s.DefaultDir()
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, response.NewBadRequest(fmt.Sprintf("解析根路径失败: %v", err))
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, response.NewBadRequest(fmt.Sprintf("访问 %s 失败: %v", absRoot, err))
	}
	if !info.IsDir() {
		return nil, response.NewBadRequest(fmt.Sprintf("%s 不是目录", absRoot))
	}
	if err := s.allowRoot(absRoot); err != nil {
		return nil, err
	}
	var metas []model.FingerFileMeta
	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		if !(strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")) {
			return nil
		}
		rel, _ := filepath.Rel(absRoot, path)
		stat, _ := d.Info()
		meta := model.FingerFileMeta{
			Path:    path,
			RelPath: rel,
			Name:    d.Name(),
		}
		if stat != nil {
			meta.SizeBytes = stat.Size()
			meta.ModifiedAt = stat.ModTime().Format(time.RFC3339)
		}
		if includeOutline {
			if loaded, rerr := s.Load(path); rerr == nil {
				content := []byte(loaded.Content)
				var fg fingerpkg.Finger
				if uerr := yaml.Unmarshal(content, &fg); uerr != nil {
					meta.ParseError = uerr.Error()
				} else {
					meta.Outline = BuildOutline(&fg)
				}
			} else {
				meta.ParseError = rerr.Error()
			}
		}
		metas = append(metas, meta)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("遍历指纹库失败: %w", walkErr)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].RelPath < metas[j].RelPath })
	return metas, nil
}

// Load 读取 path 指定的 YAML 文件。

const maxYAMLSize = 4 << 20

// allowRoot 仅登记用户通过目录列表显式选定的指纹根目录。
func (s *LibraryService) allowRoot(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return err
	}
	defer root.Close()
	s.mu.Lock()
	s.roots[abs] = struct{}{}
	s.mu.Unlock()
	return nil
}
func (s *LibraryService) openPath(path string) (*os.Root, string, string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, "", "", response.NewBadRequest("路径不能为空")
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return nil, "", "", response.NewBadRequest("仅支持 YAML 指纹文件")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, "", "", err
	}
	s.mu.RLock()
	empty := len(s.roots) == 0
	s.mu.RUnlock()
	if empty {
		s.DefaultDir()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for dir := range s.roots {
		rel, err := filepath.Rel(dir, abs)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		root, err := os.OpenRoot(dir)
		return root, rel, abs, err
	}
	return nil, "", "", response.NewBadRequest("文件不在已选择的指纹目录内")
}
func (s *LibraryService) Load(path string) (*model.LoadYAMLOutput, error) {
	root, rel, abs, err := s.openPath(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, response.NewBadRequest("只能读取普通 YAML 文件")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxYAMLSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxYAMLSize {
		return nil, response.NewBadRequest("YAML 文件超过 4 MiB 上限")
	}
	return &model.LoadYAMLOutput{Path: abs, Content: string(data)}, nil
}

// Save 在已选择目录内原子替换文件，写入失败不会破坏原有内容。
func (s *LibraryService) Save(in *model.SaveYAMLInput) error {
	if in == nil {
		return response.NewBadRequest("缺少保存参数")
	}
	root, rel, _, err := s.openPath(in.Path)
	if err != nil {
		return err
	}
	defer root.Close()
	if len(in.Content) > maxYAMLSize {
		return response.NewBadRequest("YAML 文件超过 4 MiB 上限")
	}
	var fg fingerpkg.Finger
	if err := yaml.Unmarshal([]byte(in.Content), &fg); err != nil {
		return response.NewBadRequest(fmt.Sprintf("YAML 解析失败，未保存: %v", err))
	}
	mode := os.FileMode(0o644)
	if info, err := root.Lstat(rel); err == nil {
		if !info.Mode().IsRegular() {
			return response.NewBadRequest("只能写入普通 YAML 文件")
		}
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(rel)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp := filepath.Join(dir, ".gxx-"+rand.Text())
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, writeErr := io.WriteString(f, in.Content)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(temp, rel)
}
func (s *LibraryService) Delete(path string) error {
	root, rel, _, err := s.openPath(path)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return response.NewBadRequest("只能删除普通 YAML 文件")
	}
	return root.Remove(rel)
}
