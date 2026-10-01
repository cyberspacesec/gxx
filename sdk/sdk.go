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
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/pkg/runner"
	"github.com/cyberspacesec/gxx/types"
	"os"
)

// ─────────────── 对外类型 ───────────────

// MemoryStats 是进程级运行时内存与调度统计，不代表单个 Engine 的独占内存。
type MemoryStats = runner.MemoryStats

// HostRateLimiter 是按目标主机划分的请求限流器。
type HostRateLimiter = network.HostRateLimiter

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
	OCSPServer            []string `json:"ocsp_server,omitempty"`
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"`
}

// TechStack 站点技术栈信息。
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

// TargetResult 单个目标的完整扫描结果。
type TargetResult struct {
	URL        string         `json:"url"`
	StatusCode int32          `json:"status_code"`
	Title      string         `json:"title"`
	Server     *ServerInfo    `json:"server,omitempty"`
	Matches    []FingerMatch  `json:"matches"`
	TechStack  *TechStack     `json:"tech_stack,omitempty"`
	ICP        string         `json:"icp,omitempty"`
	Certs      []CertInfo     `json:"certs,omitempty"`
	Products   []ProductMatch `json:"products,omitempty"`
}

// BaseInfo 目标基础信息（不含指纹匹配）。
type BaseInfo struct {
	Target     string      `json:"target"`
	Title      string      `json:"title"`
	StatusCode int32       `json:"status_code"`
	Server     *ServerInfo `json:"server,omitempty"`
	TechStack  *TechStack  `json:"tech_stack,omitempty"`
	ICP        string      `json:"icp,omitempty"`
	Certs      []CertInfo  `json:"certs,omitempty"`
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
