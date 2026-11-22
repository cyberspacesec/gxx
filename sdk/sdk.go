/*
Package sdk 是 GXX 指纹识别引擎的对外入口。

所有扫描 API 都是 *Engine 的方法。Engine 通过 sdk.NewEngine 构造，
所有配置由 Functional Options（With* 系列）注入；不再使用时调用 Close 释放资源。

最小用法：

	engine, err := sdk.NewEngine(ctx,
	    sdk.WithFingerOptions(sdk.FingerOptions{PocFile: "fingerYaml"}),
	    sdk.WithTimeout(15 * time.Second),
	    sdk.WithRuleConcurrency(500),
	)
	if err != nil {
	    return err
	}
	defer engine.Close()

	result, err := engine.Scan(ctx, "https://example.com")
	for _, m := range result.Matches { ... }

流式批量：

	engine.ScanCallback(ctx, []string{...}, func(r *sdk.TargetResult) bool {
	    ...
	    return true
	})
*/
package sdk

import (
	"fmt"
	"github.com/cyberspacesec/gxx/types"
	"os"
)

// ─────────────── 对外类型 ───────────────

// ServerInfo 服务器信息。
type ServerInfo struct {
	OriginalServer string `json:"original_server"`
	ServerType     string `json:"server_type"`
	Version        string `json:"version"`
}

// CertName 证书名称。
type CertName struct {
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	SerialNumber       string   `json:"serial_number_dn,omitempty"`
}

// CertInfo 证书信息。
type CertInfo struct {
	Subject               CertName `json:"subject"`
	Issuer                CertName `json:"issuer"`
	NotBefore             string   `json:"not_before"`
	NotAfter              string   `json:"not_after"`
	Valid                 bool     `json:"valid"`
	SerialNumber          string   `json:"serial_number"`
	PublicKeyAlgorithm    string   `json:"public_key_algorithm"`
	PublicKey             string   `json:"public_key,omitempty"`
	SignatureAlgorithm    string   `json:"signature_algorithm"`
	Version               int      `json:"version"`
	DNSNames              []string `json:"dns_names,omitempty"`
	IPAddresses           []string `json:"ip_addresses,omitempty"`
	EmailAddresses        []string `json:"email_addresses,omitempty"`
	URIs                  []string `json:"uris,omitempty"`
	OCSPServer            []string `json:"ocsp_server,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
	IssuingCertificateURL []string `json:"issuing_certificate_url,omitempty"`
}

// TechStack 站点技术栈信息。命名字段覆盖高价值分类，其余识别结果归入 Other，不丢弃。
type TechStack struct {
	WebServers           []string `json:"web_servers,omitempty"`
	ReverseProxies       []string `json:"reverse_proxies,omitempty"`
	JavaScriptFrameworks []string `json:"java_script_frameworks,omitempty"`
	JavaScriptLibraries  []string `json:"java_script_libraries,omitempty"`
	WebFrameworks        []string `json:"web_frameworks,omitempty"`
	StaticSiteGenerator  []string `json:"static_site_generator,omitempty"`
	ProgrammingLanguages []string `json:"programming_languages,omitempty"`
	Caching              []string `json:"caching,omitempty"`
	Security             []string `json:"security,omitempty"`
	HostingPanels        []string `json:"hosting_panels,omitempty"`
	CMS                  []string `json:"cms,omitempty"`
	Databases            []string `json:"databases,omitempty"`
	Ecommerce            []string `json:"ecommerce,omitempty"`
	CDN                  []string `json:"cdn,omitempty"`
	Analytics            []string `json:"analytics,omitempty"`
	OperatingSystems     []string `json:"operating_systems,omitempty"`
	Other                []string `json:"other,omitempty"`
}

// FingerInfo 指纹规则元信息。
type FingerInfo struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Author             string         `json:"author,omitempty"`
	Severity           string         `json:"severity,omitempty"`
	Description        string         `json:"description,omitempty"`
	Tags               []string       `json:"tags,omitempty"`
	Vendor             string         `json:"vendor,omitempty"`
	Verified           *bool          `json:"verified"`
	VerificationStatus string         `json:"verification_status"`
	Confidence         *float64       `json:"confidence"`
	References         []string       `json:"references,omitempty"`
	Created            string         `json:"created,omitempty"`
	Source             RuleSource     `json:"source"`
	Product            *ProductInfo   `json:"product,omitempty"`
	Validation         ValidationInfo `json:"validation"`
	// Services 是规则声明的 TCP/UDP 服务；HTTP 规则通常为空。
	Services []Service `json:"services,omitempty"`
	// Metadata 是规则 info.metadata 的副本，引擎只透传，不参与匹配。
	Metadata map[string]any `json:"metadata,omitempty"`
}

// FingerMatch 单条指纹匹配结果。
type FingerMatch struct {
	Info             FingerInfo     `json:"info"`
	Result           bool           `json:"result"`
	Expression       string         `json:"expression"`
	ProductVersion   string         `json:"product_version,omitempty"`
	ProductVersions  []string       `json:"product_versions,omitempty"`
	VersionConflict  bool           `json:"version_conflict,omitempty"`
	DetailsTruncated bool           `json:"details_truncated,omitempty"`
	MatchedRules     []SubRuleMatch `json:"matched_rules,omitempty"`
}

// Redirect 入口跳转链上的一跳。
type Redirect struct {
	Type     string `json:"type"`             // http（30x）/ refresh（Refresh 头或 meta）/ javascript
	Status   int32  `json:"status,omitempty"` // 发出跳转的响应的状态码
	From     string `json:"from"`
	To       string `json:"to"`
	Followed bool   `json:"followed"` // false：页面里识别出的跳转指向其他资产，没有访问
}

// TargetResult 单个目标的完整扫描结果。
//
// 一个目标由协议、主机、端口确定。入口的 HTTP 30x 总是跟随（可以指向其他主机），
// FinalURL 是跳转链最后一页的地址，StatusCode、Title、TechStack、ICP 描述该页面。
// 页面里识别出的跳转（meta refresh、脚本）只在当前页所在的资产内跟随，指向其他
// 资产时不访问，地址记入 RedirectTo。
type TargetResult struct {
	URL        string         `json:"url"`
	FinalURL   string         `json:"final_url,omitempty"`
	RedirectTo string         `json:"redirect_to,omitempty"`
	Redirects  []Redirect     `json:"redirects,omitempty"`
	StatusCode int32          `json:"status_code"`
	Title      string         `json:"title"`
	Server     *ServerInfo    `json:"server,omitempty"`
	Headers    string         `json:"headers,omitempty"` // 最终页面的原始响应头
	Matches    []FingerMatch  `json:"matches"`
	TechStack  *TechStack     `json:"tech_stack,omitempty"`
	ICP        string         `json:"icp,omitempty"`
	Certs      []CertInfo     `json:"certs,omitempty"`
	Products   []ProductMatch `json:"products,omitempty"`
	// HeaderOrder 是最终页面的响应头名称，按服务器返回的顺序，保留重复与原始大小写。
	HeaderOrder []string `json:"header_order,omitempty"`
	// TLS 是最终页面所在连接的握手摘要；明文目标为 nil。
	TLS *TLSInfo `json:"tls,omitempty"`
	// Icon 是最终页面图标的证据，WithIconEvidence 开启且页面有图标时非空。
	Icon *IconEvidence `json:"icon,omitempty"`
	// Resources 是最终页面所在资产的附属资源（robots.txt、sitemap.xml），WithResources 开启时读取。
	Resources []Resource `json:"resources,omitempty"`
	// Error 由调用方在目标扫描失败时填写，用于把失败原因随结果一起输出；
	// Scan 成功返回的结果中始终为空。
	Error string `json:"error,omitempty"`
}

// BaseInfo 目标基础信息（不含指纹匹配）。跳转字段的含义与 TargetResult 相同。
type BaseInfo struct {
	Target     string      `json:"target"`
	FinalURL   string      `json:"final_url,omitempty"`
	RedirectTo string      `json:"redirect_to,omitempty"`
	Redirects  []Redirect  `json:"redirects,omitempty"`
	Title      string      `json:"title"`
	StatusCode int32       `json:"status_code"`
	Server     *ServerInfo `json:"server,omitempty"`
	TechStack  *TechStack  `json:"tech_stack,omitempty"`
	ICP        string      `json:"icp,omitempty"`
	Certs      []CertInfo  `json:"certs,omitempty"`
	// HeaderOrder、TLS、Icon 与 Resources 的含义与 TargetResult 相同。
	HeaderOrder []string      `json:"header_order,omitempty"`
	TLS         *TLSInfo      `json:"tls,omitempty"`
	Icon        *IconEvidence `json:"icon,omitempty"`
	Resources   []Resource    `json:"resources,omitempty"`
}

// Resource 是一个附属资源。Kind 为 "robots" 或 "sitemap"；URL 是跟随同站跳转后的地址。
// Body 是正文的前 MaxBytes 字节；BodyBytes 与 SHA256 覆盖实际读取的正文（受 WithBodyLimit
// 约束）；Truncated 表示 Body 短于实际正文，或正文超过读取上限。请求失败的资源不出现。
type Resource struct {
	Kind       string `json:"kind"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body,omitempty"`
	BodyBytes  int64  `json:"body_bytes"`
	SHA256     string `json:"sha256"`
	Truncated  bool   `json:"truncated,omitempty"`
}

// IconEvidence 是最终页面图标的证据，来自计算 icon_hash 的同一次真实请求，不另发请求。
// MMH3 与 response.icon_hash 相同；Data 是图标原始字节，超过 WithIconEvidence 的上限时
// 为空并置 TooLarge；CrossOrigin 表示图标与页面不属于同一资产。图标地址是 data URL 时
// URL 只保留媒体类型部分。
type IconEvidence struct {
	URL         string `json:"url"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	MMH3        string `json:"mmh3"`
	Data        []byte `json:"data,omitempty"`
	TooLarge    bool   `json:"too_large,omitempty"`
	CrossOrigin bool   `json:"cross_origin,omitempty"`
}

// TLSInfo 是一次 TLS 握手的摘要。版本、套件、ALPN 与 JA3S 取自扫描本来就有的那次
// 握手：握手期间旁路记录服务端的 ServerHello，按公开的 JA3S 定义计算，不增加连接。
// JARM 需要另外发送 10 个构造的 ClientHello，只在 WithJARM(true) 时计算。
type TLSInfo struct {
	Version     string `json:"version"`        // 如 "TLS 1.2"
	CipherSuite string `json:"cipher_suite"`   // 如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	ALPN        string `json:"alpn,omitempty"` // 协商的应用层协议
	JA3S        string `json:"ja3s,omitempty"` // ServerHello 的 JA3S 摘要
	JARM        string `json:"jarm,omitempty"` // 62 位 JARM 指纹；全零表示目标没有以 TLS 响应
}

// FingerOptions 指纹规则加载选项（独立类型，不暴露内部 types 包）。
type FingerOptions struct {
	PocFile string // 指纹规则目录路径
	PocYaml string // 单个 YAML 文件路径
}

// toInternal 转换为内部 types.YamlFingerType。
func (o FingerOptions) toInternal() types.YamlFingerType {
	return types.YamlFingerType{
		PocFile: o.PocFile,
		PocYaml: o.PocYaml,
	}
}

// PoolStats 规则池统计信息。
type PoolStats struct {
	TotalTasks     int64 `json:"total_tasks"`
	CompletedTasks int64 `json:"completed_tasks"`
	FailedTasks    int64 `json:"failed_tasks"`
}

// NewFingerOptions 自动探测当前目录的 fingerYaml/，如果存在则用它，否则返回空 FingerOptions
// （Engine 会自动 fallback 到嵌入式指纹库）。
func NewFingerOptions() (FingerOptions, error) {
	if info, err := os.Stat("fingerYaml"); err == nil {
		if info.IsDir() {
			return FingerOptions{PocFile: "fingerYaml"}, nil
		}
	} else if !os.IsNotExist(err) {
		return FingerOptions{}, fmt.Errorf("%w: stat fingerYaml: %v", ErrLoadFinger, err)
	}
	return FingerOptions{}, nil
}
