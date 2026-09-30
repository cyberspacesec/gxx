// Package model 定义 GXX IDE HTTP API 的请求与响应数据模型。
//
// 所有字段都带 json 与 swag 标签，便于 swag init 生成准确的 OpenAPI 描述，
// 同时也作为 Vue 前端 TS 类型生成的源头。
package model

// ---- 请求测试 -----------------------------------------------------------

// RequestMode 指定请求构造模式。
type RequestMode string

const (
	// RequestModeURL 使用 URL + 方法 + 头 + body 构造请求。
	RequestModeURL RequestMode = "url"
	// RequestModeRaw 直接发送原始 HTTP 报文。
	RequestModeRaw RequestMode = "raw"
)

// SendRequestInput 是 /api/v1/request/send 的入参。
type SendRequestInput struct {
	Mode            RequestMode       `json:"mode" example:"url" enums:"url,raw"`
	Target          string            `json:"target" example:"https://example.com"`
	Method          string            `json:"method,omitempty" example:"GET"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	Raw             string            `json:"raw,omitempty"`
	UseTLS          bool              `json:"useTls" example:"true"`
	VerifyTLS       bool              `json:"verifyTls" example:"false"`
	FollowRedirects bool              `json:"followRedirects" example:"true"`
	TimeoutSeconds  int               `json:"timeoutSeconds" example:"10"`
	Proxy           string            `json:"proxy,omitempty"`
}

// CertName 证书主体/颁发者详细信息，与 types.CertName 对齐。
type CertName struct {
	CommonName         string   `json:"commonName,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
}

// CertSummary TLS 证书信息，基于 GXX 内部 types.CertInfo 提供完整字段。
type CertSummary struct {
	Subject               CertName `json:"subject"`
	SubjectDN             string   `json:"subjectDN"`
	Issuer                CertName `json:"issuer"`
	IssuerDN              string   `json:"issuerDN"`
	NotBefore             string   `json:"notBefore"`
	NotAfter              string   `json:"notAfter"`
	Valid                 bool     `json:"valid"`
	SerialNumber          string   `json:"serialNumber"`
	PublicKeyAlgorithm    string   `json:"publicKeyAlgorithm"`
	PublicKey             string   `json:"publicKey,omitempty"`
	SignatureAlgorithm    string   `json:"signatureAlgorithm"`
	Version               int      `json:"version"`
	DNSNames              []string `json:"dnsNames,omitempty"`
	IPAddresses           []string `json:"ipAddresses,omitempty"`
	EmailAddresses        []string `json:"emailAddresses,omitempty"`
	OCSPServer            []string `json:"ocspServer,omitempty"`
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`
}

// SendRequestOutput 是 SendRequest 的响应。
type SendRequestOutput struct {
	Status       int               `json:"status" example:"200"`
	StatusText   string            `json:"statusText" example:"200 OK"`
	Headers      map[string]string `json:"headers"`
	RawHeader    string            `json:"rawHeader"`
	Body         string            `json:"body"`
	BodyIsBase64 bool              `json:"bodyIsBase64"`
	BodyBytes    int               `json:"bodyBytes"`
	Latency      int64             `json:"latency"`
	IconHash     string            `json:"iconHash"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	Certs        []CertSummary     `json:"certs"`
	FinalURL     string            `json:"finalUrl"`
	RequestRaw   string            `json:"requestRaw"`
}

// ---- YAML 校验 ---------------------------------------------------------

// ValidateYAMLInput 是 /api/v1/yaml/validate 的入参。
type ValidateYAMLInput struct {
	Content string `json:"content"`
}

// YAMLValidationError 单条 YAML 错误。
type YAMLValidationError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

// RuleOutline 单条 rule 概要。
type RuleOutline struct {
	Key        string `json:"key"`
	Type       string `json:"type"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Expression string `json:"expression"`
}

// FingerOutline 指纹概要，前端展示用。
type FingerOutline struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Author      string        `json:"author"`
	Severity    string        `json:"severity"`
	Tags        string        `json:"tags"`
	Description string        `json:"description"`
	Expression  string        `json:"expression"`
	RuleKeys    []string      `json:"ruleKeys"`
	Rules       []RuleOutline `json:"rules"`
	SetVars     []string      `json:"setVars"`
}

// ValidateYAMLOutput 是 ValidateYAML 的响应。
type ValidateYAMLOutput struct {
	Valid   bool                  `json:"valid"`
	Errors  []YAMLValidationError `json:"errors"`
	Outline *FingerOutline        `json:"outline,omitempty"`
}

// ---- 运行指纹 ----------------------------------------------------------

// RunFingerprintInput 是 /api/v1/finger/run 的入参。
type RunFingerprintInput struct {
	YAML            string `json:"yaml"`
	Target          string `json:"target"`
	Proxy           string `json:"proxy,omitempty"`
	TimeoutSeconds  int    `json:"timeoutSeconds"`
	UseTLS          bool   `json:"useTls"`
	VerifyTLS       bool   `json:"verifyTls"`
	FollowRedirects bool   `json:"followRedirects"`
}

// RuleRun 单条 rule 的执行记录。
type RuleRun struct {
	Key           string `json:"key"`
	Expression    string `json:"expression"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	URLEvaluated  string `json:"urlEvaluated"`
	RequestRaw    string `json:"requestRaw"`
	ResponseRaw   string `json:"responseRaw"`
	StatusCode    int32  `json:"statusCode"`
	Latency       int64  `json:"latency"`
	Result        bool   `json:"result"`
	HTTPError     string `json:"httpError"`
	CELError      string `json:"celError"`
	NonBoolResult bool   `json:"nonBoolResult"`
}

// VarEntry varMap 单项。
type VarEntry struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RunFingerprintOutput 是 RunFingerprint 的响应。
type RunFingerprintOutput struct {
	FinalExpression string         `json:"finalExpression"`
	FinalResult     bool           `json:"finalResult"`
	ExpressionError string         `json:"expressionError"`
	Rules           []RuleRun      `json:"rules"`
	Variables       []VarEntry     `json:"variables"`
	FingerOutline   *FingerOutline `json:"fingerOutline,omitempty"`
}

// ---- CEL 调试 ----------------------------------------------------------

// EvaluateCELInput 是 /api/v1/cel/evaluate 的入参。
type EvaluateCELInput struct {
	Expression string         `json:"expression"`
	Variables  map[string]any `json:"variables"`
}

// EvaluateCELOutput 是 EvaluateCEL 的响应。
type EvaluateCELOutput struct {
	Result string `json:"result"`
	Type   string `json:"type"`
}

// ---- 指纹库 -----------------------------------------------------------

// FingerFileMeta 单个 YAML 文件的元数据。
type FingerFileMeta struct {
	Path       string         `json:"path"`
	RelPath    string         `json:"relPath"`
	Name       string         `json:"name"`
	SizeBytes  int64          `json:"sizeBytes"`
	ModifiedAt string         `json:"modifiedAt"`
	Outline    *FingerOutline `json:"outline,omitempty"`
	ParseError string         `json:"parseError,omitempty"`
}

// ListLibraryInput 是 /api/v1/library/list 的入参。
type ListLibraryInput struct {
	RootDir        string `form:"rootDir"`
	IncludeOutline bool   `form:"includeOutline"`
}

// SaveYAMLInput 是 /api/v1/library/save 的入参。
type SaveYAMLInput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// DefaultLibraryDirOutput 是 /api/v1/library/default 的响应。
type DefaultLibraryDirOutput struct {
	Path string `json:"path"`
}

// LoadYAMLOutput 是 /api/v1/library/load 的响应。
type LoadYAMLOutput struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}
