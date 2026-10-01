/*
Package runner sync.Pool 集合：RuleTask / varMap / FingerMatch。
进程级（无业务状态），任意 Runner 实例都可以安全复用。
*/
package runner

import (
	"github.com/cyberspacesec/gxx/v2/pkg/cel"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"sync"
)

var (
	ruleTaskPool = sync.Pool{New: func() interface{} { return &RuleTask{} }}
	varMapPool   = sync.Pool{New: func() interface{} { return make(map[string]any, 16) }}
	matchPool    = sync.Pool{New: func() interface{} { return &FingerMatch{} }}
	libPool      = sync.Pool{New: func() any { return cel.NewCustomLib() }}
	batchPool    = sync.Pool{New: func() any { return &ruleBatch{} }}
)

const ruleBatchSize = 8

type ruleBatch struct {
	tasks [ruleBatchSize]*RuleTask
	count int
}

func acquireRuleBatch() *ruleBatch { return batchPool.Get().(*ruleBatch) }

func releaseRuleBatch(batch *ruleBatch) {
	*batch = ruleBatch{}
	batchPool.Put(batch)
}

func acquireLibrary(plan *cel.PreparedLibrary) *cel.CustomLib {
	lib := libPool.Get().(*cel.CustomLib)
	plan.InitEvaluation(lib)
	return lib
}

func releaseLibrary(lib *cel.CustomLib) {
	lib.Reset()
	libPool.Put(lib)
}

func acquireRuleTask() *RuleTask {
	t := ruleTaskPool.Get().(*RuleTask)
	*t = RuleTask{pooled: true}
	return t
}

func releaseRuleTask(t *RuleTask) {
	if t == nil {
		return
	}
	*t = RuleTask{}
	ruleTaskPool.Put(t)
}

func acquireVarMap() map[string]any {
	return varMapPool.Get().(map[string]any)
}

func releaseVarMap(m map[string]any) {
	if m == nil {
		return
	}
	for k := range m {
		delete(m, k)
	}
	varMapPool.Put(m)
}

func acquireFingerMatch(fg *finger.Finger) *FingerMatch {
	m := matchPool.Get().(*FingerMatch)
	*m = FingerMatch{Finger: fg}
	return m
}

func releaseFingerMatch(m *FingerMatch) {
	if m == nil {
		return
	}
	*m = FingerMatch{}
	matchPool.Put(m)
}
