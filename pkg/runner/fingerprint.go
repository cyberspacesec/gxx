/*
Package runner 指纹规则集（实例化）。

每个 Runner 持有独立的 *FingerStore；加载成功后整体发布只读规则快照。
*/
package runner

import (
	"fmt"
	fingerYaml "github.com/cyberspacesec/gxx/fingerYaml"
	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/logger"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FingerStore 指纹规则集合实例。
type FingerStore struct {
	mu              sync.RWMutex
	fingers         []*finger.Finger
	plans           []fingerExecutionPlan
	log             logger.Sink
	captureEvidence bool
}

// 执行清单与只读规则快照同时发布，按连续索引取得程序及调度条件。
type fingerExecutionPlan struct {
	finger    *finger.Finger
	prepared  *cel.PreparedLibrary
	cacheOnly bool
}

// NewFingerStore 创建空 store。
func NewFingerStore(logs ...logger.Sink) *FingerStore {
	log := logger.Current()
	if len(logs) > 0 && logs[0] != nil {
		log = logs[0]
	}
	return &FingerStore{log: log}
}

// Load 加载指纹规则。解析失败时保留原规则集，成功后整体替换。
func (fs *FingerStore) Load(options types.YamlFingerType) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var next []*finger.Finger

	if options.PocFile == "" && options.PocYaml == "" {
		fs.log.Info("使用默认指纹库")
		fin, err := fingerYaml.GetFingerYaml()
		if err != nil {
			return fmt.Errorf("加载嵌入指纹库失败: %w", err)
		}
		next = fin
		fs.fingers = next
		fs.prepare()
		return nil
	}

	if options.PocFile != "" {
		fs.log.Info("加载yaml文件目录：%s", options.PocFile)
		err := filepath.WalkDir(options.PocFile, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && common.IsYamlFile(path) {
				poc, err := finger.Read(path)
				if err != nil {
					return fmt.Errorf("读取 %s: %w", path, err)
				}
				if poc != nil {
					relative, err := filepath.Rel(options.PocFile, path)
					if err != nil {
						return err
					}
					poc.Source.Path = filepath.ToSlash(relative)
					next = append(next, poc)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		fs.fingers = next
		fs.prepare()
		return nil
	}

	if options.PocYaml != "" {
		fs.log.Info("加载yaml文件：%s", options.PocYaml)
		if !common.IsYamlFile(options.PocYaml) {
			return fmt.Errorf("%s 不是有效的yaml文件", options.PocYaml)
		}
		poc, err := finger.Read(options.PocYaml)
		if err != nil {
			return fmt.Errorf("读取yaml文件出错: %w", err)
		}
		if poc != nil {
			next = append(next, poc)
		}
	}
	fs.fingers = next
	fs.prepare()
	return nil
}

func (fs *FingerStore) executionSnapshot() []fingerExecutionPlan {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.plans
}

// prepare 只编译无动态声明的规则，动态 set/output 保持执行时的类型推导行为。
func (fs *FingerStore) prepare() {
	plans := make([]fingerExecutionPlan, len(fs.fingers))
	for i, fg := range fs.fingers {
		plans[i].finger = fg
		if len(fg.Set) > 0 || len(fg.Payloads.Payloads) > 0 {
			continue
		}
		keys := make([]string, 0, len(fg.Rules))
		expressions := make([]string, 0, len(fg.Rules)+1)
		dynamic := false
		for _, rule := range fg.Rules {
			keys = append(keys, rule.Key)
			expressions = append(expressions, rule.Value.Expression)
			if len(rule.Value.Output) > 0 {
				dynamic = true
			}
		}
		if dynamic {
			continue
		}
		expressions = append(expressions, fg.Expression)
		if plan, err := cel.PrepareLibrary(keys, expressions, fs.captureEvidence); err == nil {
			plans[i].prepared = plan
			plans[i].cacheOnly = plan.BatchSafe() && hasOnlyRootRequests(fg)
		}
	}
	fs.plans = plans
}

func hasOnlyRootRequests(fg *finger.Finger) bool {
	for _, rule := range fg.Rules {
		req := rule.Value.Request
		path := strings.TrimSpace(req.Path)
		if !strings.EqualFold(req.Method, "GET") || req.Type != "" && !strings.EqualFold(req.Type, common.HttpType) || path != "" && path != "/" || req.FollowRedirects || len(req.Headers) != 0 || req.Body != "" || req.Raw != "" {
			return false
		}
	}
	return true
}

// Count 返回当前指纹数量。
func (fs *FingerStore) Count() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.fingers)
}

// Metadata 返回独立的元数据副本，不暴露可修改的执行规则。
func (fs *FingerStore) Metadata() []finger.Metadata {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	result := make([]finger.Metadata, len(fs.fingers))
	for index, rule := range fs.fingers {
		result[index] = finger.Metadata{ID: rule.Id, Info: rule.Info, Source: rule.Source}
		result[index].Info.Reference = append([]string(nil), rule.Info.Reference...)
		result[index].Transport, result[index].Expression = rule.Transport, rule.Expression
		result[index].Detection = make([]finger.DetectionRule, len(rule.Rules))
		for position, subrule := range rule.Rules {
			value := finger.DetectionRule{Key: subrule.Key, Transport: subrule.Value.Request.Type, Method: subrule.Value.Request.Method, Path: subrule.Value.Request.Path, Expression: subrule.Value.Expression}
			for _, output := range subrule.Value.Output {
				key, keyOK := output.Key.(string)
				expression, expressionOK := output.Value.(string)
				if keyOK && expressionOK {
					if value.Output == nil {
						value.Output = make(map[string]string)
					}
					value.Output[key] = expression
				}
			}
			result[index].Detection[position] = value
		}
	}
	return result
}
