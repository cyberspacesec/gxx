package finger

// Metadata 展示规则来源和检测依据，不暴露表达式树及执行状态。
type Metadata struct {
	ID         string
	Info       Info
	Source     Source
	Transport  string
	Expression string
	Detection  []DetectionRule
}

type DetectionRule struct {
	Key        string
	Transport  string
	Method     string
	Path       string
	Expression string
	Output     map[string]string
}
