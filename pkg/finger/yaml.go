/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: yaml.go
    @Date: 2025/2/21 下午2:36*
*/
package finger

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v2"
)

// FingerFile 配置poc文件目录
const FingerFile = "fingerYaml"
const (
	HttpType = "http"
	TcpType  = "tcp"
	UdpType  = "udp"
)

// normalizeRuleType 归一化并校验规则传输类型，只接受实际实现的 http、tcp、udp。
//
// 归一化消除 `type: HTTP` 这类大小写不一致，使探活判断与执行分支使用同一取值。
// 未实现的类型在加载期报错：留到执行期只会在调试日志里出现一行，规则表现为
// 永不命中，还会为每个目标占用一次限流名额。TLS 不是独立类型，由 host 的
// ssl:// / tls:// / https:// 前缀或 443 端口决定。
func normalizeRuleType(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "", HttpType, TcpType, UdpType:
		return normalized, nil
	}
	return "", fmt.Errorf("不支持的请求类型 %q（支持 http、tcp、udp；TLS 由 host 的 ssl:// 前缀或 443 端口决定）", raw)
}

type Finger struct {
	Id         string        `yaml:"id"`        //  脚本名称
	Transport  string        `yaml:"transport"` // 传输方式，该字段用于指定发送数据包的协议，该字段用于指定发送数据包的协议:①tcp ②udp ③http
	Set        yaml.MapSlice `yaml:"set"`       // 全局变量定义，该字段用于定义全局变量。比如随机数，反连平台等
	Payloads   Payloads      `yaml:"payloads"`
	Rules      RuleMapSlice  `yaml:"rules"`
	Expression string        `yaml:"expression"`
	Info       Info          `yaml:"info"`
	Source     Source        `yaml:"-"`
}

// Source 记录实际加载的规则文件；摘要只在加载时计算。
type Source struct {
	Path    string
	SHA256  string
	Builtin bool
}
type Payloads struct {
	Continue bool          `yaml:"continue"`
	Payloads yaml.MapSlice `yaml:"payloads"`
}

// RuleMap 用于帮助yaml解析，保证Rule有序
type RuleMap struct {
	Key   string
	Value Rule
}

// RuleMapSlice 用于帮助yaml解析，保证Rule有序
type RuleMapSlice []RuleMap

type Rule struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
}
type RuleRequest struct {
	Type            string            `yaml:"type"`         // 传输方式，默认 http，可选 http/tcp/udp；其余值在加载时报错
	Host            string            `yaml:"host"`         // tcp/udp 连接地址，格式见 network.ParseEndpoint；为空时使用扫描目标
	Data            string            `yaml:"data"`         // tcp/udp 发送的内容
	DataType        string            `yaml:"data-type"`    // tcp/udp 发送的数据类型，默认字符串
	ReadSize        int               `yaml:"read-size"`    // tcp/udp 读取内容的长度
	ReadTimeout     int               `yaml:"read-timeout"` // tcp/udp 单次接收的总时长上限（秒）
	ReadIdle        int               `yaml:"read-idle"`    // tcp 收到数据后等待后续分段的空闲时间（毫秒）；未设置时自适应
	Raw             string            `yaml:"raw"`          // raw 专用
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects *bool             `yaml:"follow_redirects,omitempty"` // 是否跟随重定向：true 跟随，false 不跟随，未声明时默认跟随
}

// ShouldFollowRedirects 返回该请求是否跟随重定向。
// 未声明 follow_redirects 时默认跟随，与规则格式文档以及 IDE 生成的规则保持一致。
func (r RuleRequest) ShouldFollowRedirects() bool {
	return r.FollowRedirects == nil || *r.FollowRedirects
}

// Info 以下开始是 信息部分
type Info struct {
	Name             string         `yaml:"name"`
	Author           string         `yaml:"author"`
	Severity         string         `yaml:"severity"`
	Verified         bool           `yaml:"verified"`
	VerifiedDeclared bool           `yaml:"-"`
	Description      string         `yaml:"description"`
	Reference        []string       `yaml:"reference"`
	Affected         string         `yaml:"affected"`  // 影响版本
	Solutions        string         `yaml:"solutions"` // 解决方案
	Tags             string         `yaml:"tags"`      // 标签
	Classification   Classification `yaml:"classification"`
	Created          string         `yaml:"created"` // create time
	// Product 是规则声明的产品信息，未声明时为 nil；调用方自有规则可以不声明。
	Product *Product `yaml:"product"`
	// Services 是 TCP/UDP 规则识别的服务；HTTP 规则可以省略。
	Services []Service `yaml:"services"`
	// Metadata 是任意附加信息，引擎只透传，不参与匹配。
	Metadata map[string]any `yaml:"metadata"`
}

// UnmarshalYAML 区分未填写 verified 与明确的 false，保留原始声明；附加元数据中的嵌套
// 映射统一为 map[string]any。
func (i *Info) UnmarshalYAML(unmarshal func(any) error) error {
	type plainInfo Info
	var value plainInfo
	if err := unmarshal(&value); err != nil {
		return err
	}
	var declaration struct {
		Verified *bool `yaml:"verified"`
	}
	if err := unmarshal(&declaration); err != nil {
		return err
	}
	*i = Info(value)
	i.VerifiedDeclared = declaration.Verified != nil
	if i.Metadata != nil {
		i.Metadata = normalizeMetadata(i.Metadata).(map[string]any)
	}
	return nil
}

type Classification struct {
	CvssMetrics string  `yaml:"cvss-metrics"`
	CvssScore   float64 `yaml:"cvss-score"`
	CveId       string  `yaml:"cve-id"`
	CweId       string  `yaml:"cwe-id"`
}

// Load 加载yaml文件
func Load(fileName string, Fingers embed.FS) (*Finger, error) {
	p := &Finger{}
	// 构造候选路径，优先尝试包含 fingerYaml/ 前缀的路径，失败则回退到原始路径
	var candidates []string
	if strings.HasPrefix(fileName, "fingerYaml/") {
		candidates = []string{fileName, strings.TrimPrefix(fileName, "fingerYaml/")}
	} else {
		candidates = []string{"fingerYaml/" + fileName, fileName}
	}

	var (
		yamlFile []byte
		err      error
		filePath string
	)

	for _, candidate := range candidates {
		filePath = candidate
		yamlFile, err = Fingers.ReadFile(candidate)
		if err == nil {
			break
		}
	}

	if err != nil {
		fmt.Printf("[-] load poc %s error1: %v\n", filePath, err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		fmt.Printf("[-] load poc %s error2: %v\n", filePath, err)
		return nil, err
	}
	p.Source = Source{Path: filepath.ToSlash(filePath), SHA256: fmt.Sprintf("%x", sha256.Sum256(yamlFile)), Builtin: true}
	return p, err
}

// Read 获取yaml文件内容
func Read(fileName string) (*Finger, error) {
	p := &Finger{}

	content, err := os.ReadFile(fileName)
	if err != nil {
		return p, err
	}
	return Parse(content, filepath.Base(fileName))
}

// Parse 解析规则内容；path 记为规则来源，摘要按内容计算。
func Parse(content []byte, path string) (*Finger, error) {
	p := &Finger{}
	if err := yaml.Unmarshal(content, p); err != nil {
		return p, err
	}
	p.Source = Source{Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	return p, nil
}

// IsHTTPType 报告指纹是否包含 HTTP 规则。YAML 加载时类型已归一化为小写；
// 比较时仍忽略大小写与空白，使不经 YAML 直接构造的规则得到相同结论。
func (finger *Finger) IsHTTPType() bool {
	for _, rule := range finger.Rules {
		reqType := strings.TrimSpace(rule.Value.Request.Type)
		if len(reqType) == 0 || strings.EqualFold(reqType, HttpType) {
			return true
		}
	}
	return false
}

// UnmarshalYAML 保持规则在源文件中的顺序，重复名称采用最后一次定义。
// 所有解析状态属于当前调用；并发加载规则不需要共享计数器或全局锁。
func (m *RuleMapSlice) UnmarshalYAML(unmarshal func(any) error) error {
	var ordered yaml.MapSlice
	if err := unmarshal(&ordered); err != nil {
		return err
	}
	var rules map[string]Rule
	if err := unmarshal(&rules); err != nil {
		return err
	}
	last := make(map[string]int, len(ordered))
	for i, item := range ordered {
		key, ok := item.Key.(string)
		if !ok {
			return fmt.Errorf("规则名称必须是字符串")
		}
		last[key] = i
	}
	result := make(RuleMapSlice, 0, len(rules))
	for i, item := range ordered {
		key := item.Key.(string)
		if last[key] != i {
			continue
		}
		rule := rules[key]
		// 在加载期归一化并校验传输类型：后续 IsHTTPType / 执行分支都按小写比较，
		// 未知类型在这里就报错，不留到扫描期静默不命中。
		normalized, err := normalizeRuleType(rule.Request.Type)
		if err != nil {
			return fmt.Errorf("规则 %s: %w", key, err)
		}
		rule.Request.Type = normalized
		// 方法统一为大写，HTTP 规则省略时按 GET；缓存与请求合并都按 GET 判断，
		// 留空会让每条规则各发一次请求。
		rule.Request.Method = strings.ToUpper(strings.TrimSpace(rule.Request.Method))
		if rule.Request.Method == "" && (normalized == "" || normalized == HttpType) && rule.Request.Raw == "" {
			rule.Request.Method = "GET"
		}
		result = append(result, RuleMap{Key: key, Value: rule})
	}
	*m = result
	return nil
}
