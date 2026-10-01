package sdk

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/cyberspacesec/gxx/v2/pkg/cel"
	"github.com/cyberspacesec/gxx/v2/pkg/finger"
	"github.com/cyberspacesec/gxx/v2/pkg/runner"
)

// Version 是 SDK 源版本，不能作为被识别产品的版本。
const Version = "2.0.0"

type RuleSource struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version,omitempty"`
}

// ProductInfo 是独立产品目录中的信息；未知厂商、CPE 和分类不从名称自动推断。
type ProductInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor,omitempty"`
	Category    string   `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	CPE         []string `json:"cpe,omitempty"`
	References  []string `json:"references,omitempty"`
	Description string   `json:"description,omitempty"`
}
type ProductDefinition struct {
	ProductInfo
	RuleIDs []string `json:"rule_ids"`
}

// ValidationInfo 描述测试方法和样本范围，不把有限样本测试当作实际准确率。
type ValidationInfo struct {
	Status          string `json:"status"`
	Method          string `json:"method,omitempty"`
	PositiveSamples int    `json:"positive_samples,omitempty"`
	NegativeSamples int    `json:"negative_samples,omitempty"`
	ReviewedAt      string `json:"reviewed_at,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

type RuleAssessment struct {
	RuleID     string         `json:"rule_id"`
	RuleSHA256 string         `json:"rule_sha256"`
	Validation ValidationInfo `json:"validation"`
	Confidence *float64       `json:"confidence"`
}

// DetectionRule 展示识别依据与版本提取表达式，不包含执行时的响应数据。
type DetectionRule struct {
	Key        string            `json:"key"`
	Transport  string            `json:"transport"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Expression string            `json:"expression"`
	Output     map[string]string `json:"output,omitempty"`
}
type RuleMetadata struct {
	Info            FingerInfo      `json:"info"`
	Transport       string          `json:"transport"`
	Expression      string          `json:"expression"`
	Detection       []DetectionRule `json:"detection"`
	MissingMetadata []string        `json:"missing_metadata,omitempty"`
}

// MatchEvidence 是实际求值分支的证据，位置使用原字段的字节区间。
type MatchEvidence cel.Evidence

type SubRuleMatch struct {
	Key               string            `json:"key"`
	Expression        string            `json:"expression"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	URL               string            `json:"url"`
	StatusCode        int32             `json:"status_code"`
	Evidence          []MatchEvidence   `json:"evidence,omitempty"`
	EvidenceTruncated bool              `json:"evidence_truncated,omitempty"`
	Outputs           map[string]string `json:"outputs,omitempty"`
}

// ProductMatch 按目录 ID 归并同一产品，保留每个命中规则的来源。
// 版本冲突时 Version 留空，并在 Versions 中保留各自结果。
type ProductMatch struct {
	ProductInfo
	Version         string   `json:"version,omitempty"`
	Versions        []string `json:"versions,omitempty"`
	VersionConflict bool     `json:"version_conflict,omitempty"`
	RuleIDs         []string `json:"rule_ids"`
}

//go:embed catalog.json
var catalogData []byte
var catalogOnce sync.Once
var builtinCatalog struct {
	Products    []ProductDefinition       `json:"products"`
	Validations map[string]RuleAssessment `json:"validations"`
}
var catalogError error

func loadCatalog() error {
	catalogOnce.Do(func() {
		catalogError = json.Unmarshal(catalogData, &builtinCatalog)
		if catalogError == nil {
			catalogError = validateProductDefinitions(builtinCatalog.Products)
		}
		if catalogError == nil {
			assessments := make([]RuleAssessment, 0, len(builtinCatalog.Validations))
			for id, assessment := range builtinCatalog.Validations {
				if id != assessment.RuleID {
					catalogError = fmt.Errorf("产品目录的测试记录 ID 不一致: %s", id)
					return
				}
				assessments = append(assessments, assessment)
			}
			catalogError = validateAssessments(assessments)
		}
	})
	return catalogError
}

// ProductCatalog 返回内置产品目录的独立副本，便于系统扩展及导入。
func ProductCatalog() ([]ProductDefinition, error) {
	if err := loadCatalog(); err != nil {
		return nil, err
	}
	return cloneProductDefinitions(builtinCatalog.Products), nil
}

// RuleCatalog 返回全部规则的元数据、检测条件和待核对字段，适用于系统导入。
func (e *Engine) RuleCatalog(ctx context.Context) ([]RuleMetadata, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if e.IsClosed() {
			return nil, ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	metadata := e.runner.RuleMetadata()
	result := make([]RuleMetadata, len(metadata))
	for index, value := range metadata {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current := RuleMetadata{Info: e.convertFingerInfo(value), Expression: value.Expression}
		versionExtractor := false
		for _, rule := range value.Detection {
			transport := strings.ToLower(strings.TrimSpace(rule.Transport))
			if transport == "" {
				transport = "http"
			}
			if current.Transport == "" {
				current.Transport = transport
			} else if current.Transport != transport {
				current.Transport = "mixed"
			}
			current.Detection = append(current.Detection, DetectionRule{Key: rule.Key, Transport: transport, Method: rule.Method, Path: rule.Path, Expression: rule.Expression, Output: rule.Output})
			_, exists := rule.Output["product_version"]
			versionExtractor = versionExtractor || exists
		}
		if current.Info.Product == nil {
			current.MissingMetadata = append(current.MissingMetadata, "product-catalog")
		}
		if current.Info.Vendor == "" {
			current.MissingMetadata = append(current.MissingMetadata, "vendor")
		}
		if len(current.Info.Tags) == 0 {
			current.MissingMetadata = append(current.MissingMetadata, "tags")
		}
		if len(current.Info.References) == 0 {
			current.MissingMetadata = append(current.MissingMetadata, "references")
		}
		if current.Info.Validation.Status == "not-tested" {
			current.MissingMetadata = append(current.MissingMetadata, "sample-validation")
		}
		if !versionExtractor {
			current.MissingMetadata = append(current.MissingMetadata, "version-extractor")
		}
		result[index] = current
	}
	return result, nil
}

func (e *Engine) convertFingerInfo(metadata finger.Metadata) FingerInfo {
	info := metadata.Info
	result := FingerInfo{ID: metadata.ID, Name: info.Name, Author: info.Author, Severity: info.Severity,
		Description: info.Description, Tags: splitTags(info.Tags), Created: info.Created,
		References: validReferences(info.Reference), Source: RuleSource{Path: metadata.Source.Path, SHA256: metadata.Source.SHA256},
		VerificationStatus: "unknown", Validation: ValidationInfo{Status: "not-tested"}}
	if info.VerifiedDeclared {
		verified := info.Verified
		result.Verified = &verified
		result.VerificationStatus = "unverified"
		if verified {
			result.VerificationStatus = "declared-verified"
		}
	}
	if metadata.Source.Builtin {
		result.Source.Version = Version
	} else {
		result.Source.Version = e.cfg.ruleSourceVersion
	}
	if product, exists := e.products[metadata.ID]; exists {
		product = cloneProduct(product)
		result.Product, result.Vendor = &product, product.Vendor
		for _, tag := range product.Tags {
			if !slices.Contains(result.Tags, tag) {
				result.Tags = append(result.Tags, tag)
			}
		}
		for _, reference := range product.References {
			if !slices.Contains(result.References, reference) {
				result.References = append(result.References, reference)
			}
		}
	}
	if assessment, exists := e.assessments[metadata.ID]; exists && strings.EqualFold(assessment.RuleSHA256, metadata.Source.SHA256) {
		result.Validation = assessment.Validation
		if assessment.Confidence != nil {
			confidence := *assessment.Confidence
			result.Confidence = &confidence
		}
	}
	return result
}

func cloneAssessments(assessments []RuleAssessment) []RuleAssessment {
	result := slices.Clone(assessments)
	for index := range result {
		if result[index].Confidence != nil {
			confidence := *result[index].Confidence
			result[index].Confidence = &confidence
		}
	}
	return result
}
func validateAssessments(assessments []RuleAssessment) error {
	seen := make(map[string]bool)
	for _, assessment := range assessments {
		digest, err := hex.DecodeString(assessment.RuleSHA256)
		if assessment.RuleID == "" || seen[assessment.RuleID] || err != nil || len(digest) != 32 {
			return fmt.Errorf("%w: 测试记录需要唯一规则 ID 和 SHA256", ErrInvalidOption)
		}
		seen[assessment.RuleID] = true
		validation := assessment.Validation
		if validation.Status == "" || validation.Method == "" || validation.Scope == "" || validation.PositiveSamples < 0 || validation.NegativeSamples < 0 || validation.PositiveSamples+validation.NegativeSamples == 0 {
			return fmt.Errorf("%w: 测试记录需要方法、样本数和适用范围", ErrInvalidOption)
		}
		if assessment.Confidence != nil && (math.IsNaN(*assessment.Confidence) || math.IsInf(*assessment.Confidence, 0) || *assessment.Confidence < 0 || *assessment.Confidence > 1) {
			return fmt.Errorf("%w: 置信度必须在 [0, 1] 内", ErrInvalidOption)
		}
	}
	return nil
}

func splitTags(value string) []string {
	var result []string
	for _, tag := range strings.Split(value, ",") {
		tag = strings.TrimSpace(tag)
		if tag != "" && !slices.Contains(result, tag) {
			result = append(result, tag)
		}
	}
	return result
}

func validReferences(references []string) []string {
	var result []string
	for _, reference := range references {
		reference = strings.TrimSpace(reference)
		parsed, err := url.Parse(reference)
		if err != nil || !validReferenceURL(parsed) {
			continue
		}
		if !slices.Contains(result, reference) {
			result = append(result, reference)
		}
	}
	return result
}

func validReferenceURL(parsed *url.URL) bool {
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && host != "" && host != "example.com" && !strings.HasSuffix(host, ".example.com") && parsed.User == nil
}

func productIndex(overrides []ProductDefinition) (map[string]ProductInfo, error) {
	if err := loadCatalog(); err != nil {
		return nil, err
	}
	products := make(map[string]ProductInfo)
	rules := make(map[string]string)
	for _, definition := range builtinCatalog.Products {
		products[definition.ID] = definition.ProductInfo
		for _, ruleID := range definition.RuleIDs {
			rules[ruleID] = definition.ID
		}
	}
	for _, definition := range overrides {
		products[definition.ID] = cloneProduct(definition.ProductInfo)
		for _, ruleID := range definition.RuleIDs {
			rules[ruleID] = definition.ID
		}
	}
	index := make(map[string]ProductInfo, len(rules))
	for ruleID, productID := range rules {
		index[ruleID] = products[productID]
	}
	return index, nil
}

func cloneProduct(product ProductInfo) ProductInfo {
	product.Tags, product.Aliases = slices.Clone(product.Tags), slices.Clone(product.Aliases)
	product.CPE, product.References = slices.Clone(product.CPE), slices.Clone(product.References)
	return product
}
func cloneProductDefinitions(products []ProductDefinition) []ProductDefinition {
	result := slices.Clone(products)
	for index := range result {
		result[index].ProductInfo = cloneProduct(result[index].ProductInfo)
		result[index].RuleIDs = slices.Clone(result[index].RuleIDs)
	}
	return result
}
func validateProductDefinitions(products []ProductDefinition) error {
	ids, rules := make(map[string]bool), make(map[string]bool)
	for _, product := range products {
		if strings.TrimSpace(product.ID) == "" || strings.TrimSpace(product.Name) == "" || len(product.RuleIDs) == 0 {
			return fmt.Errorf("%w: 产品目录需要 ID、名称和规则 ID", ErrInvalidOption)
		}
		if ids[product.ID] {
			return fmt.Errorf("%w: 产品 ID 重复: %s", ErrInvalidOption, product.ID)
		}
		ids[product.ID] = true
		for _, id := range product.RuleIDs {
			if id == "" || rules[id] {
				return fmt.Errorf("%w: 产品规则 ID 为空或重复: %s", ErrInvalidOption, id)
			}
			rules[id] = true
		}
		for _, reference := range product.References {
			parsed, err := url.Parse(reference)
			if err != nil || !validReferenceURL(parsed) {
				return fmt.Errorf("%w: 产品参考链接无效: %s", ErrInvalidOption, reference)
			}
		}
		for _, cpe := range product.CPE {
			if !validCPE(cpe) {
				return fmt.Errorf("%w: CPE 格式无效: %s", ErrInvalidOption, cpe)
			}
		}
	}
	return nil
}

// CPE 2.3 的属性可包含转义冒号；只按未转义分隔符拆分 11 个属性。
func validCPE(value string) bool {
	if !strings.HasPrefix(value, "cpe:2.3:") {
		return false
	}
	attributes := make([]string, 0, 11)
	start, escaped := len("cpe:2.3:"), false
	for index := start; index < len(value); index++ {
		if value[index] < ' ' || value[index] >= 127 {
			return false
		}
		if escaped {
			escaped = false
			continue
		}
		if value[index] == '\\' {
			escaped = true
		} else if value[index] == ':' {
			attributes = append(attributes, value[start:index])
			start = index + 1
		} else if value[index] <= ' ' || value[index] >= 127 {
			return false
		}
	}
	attributes = append(attributes, value[start:])
	if escaped || len(attributes) != 11 || (attributes[0] != "a" && attributes[0] != "h" && attributes[0] != "o" && attributes[0] != "*" && attributes[0] != "-") {
		return false
	}
	for _, attribute := range attributes {
		if attribute == "" {
			return false
		}
	}
	return true
}

func convertSubRuleMatches(matches []runner.SubRuleMatch) []SubRuleMatch {
	if len(matches) == 0 {
		return nil
	}
	result := make([]SubRuleMatch, len(matches))
	for index, match := range matches {
		evidence := make([]MatchEvidence, len(match.Evidence))
		for item := range match.Evidence {
			evidence[item] = MatchEvidence(match.Evidence[item])
		}
		result[index] = SubRuleMatch{Key: match.Key, Expression: match.Expression, Method: match.Method, Path: match.Path, URL: match.URL,
			StatusCode: match.StatusCode, Evidence: evidence, EvidenceTruncated: match.EvidenceTruncated, Outputs: match.Outputs}
	}
	return result
}

func aggregateProducts(matches []FingerMatch) []ProductMatch {
	indices := make(map[string]int)
	var result []ProductMatch
	for _, match := range matches {
		if !match.Result {
			continue
		}
		key := "rule:" + match.Info.ID
		product := ProductInfo{Name: match.Info.Name}
		if match.Info.Product != nil {
			product = cloneProduct(*match.Info.Product)
			key = "product:" + product.ID
		}
		index, found := indices[key]
		if !found {
			index = len(result)
			indices[key] = index
			result = append(result, ProductMatch{ProductInfo: product})
		}
		current := &result[index]
		if !slices.Contains(current.RuleIDs, match.Info.ID) {
			current.RuleIDs = append(current.RuleIDs, match.Info.ID)
		}
		for _, version := range match.ProductVersions {
			if !slices.Contains(current.Versions, version) {
				current.Versions = append(current.Versions, version)
			}
		}
		if len(match.ProductVersions) == 0 && match.ProductVersion != "" && !slices.Contains(current.Versions, match.ProductVersion) {
			current.Versions = append(current.Versions, match.ProductVersion)
		}
		current.VersionConflict = current.VersionConflict || match.VersionConflict
	}
	for index := range result {
		current := &result[index]
		sort.Strings(current.RuleIDs)
		sort.Strings(current.Versions)
		if len(current.Versions) == 1 && !current.VersionConflict {
			current.Version = current.Versions[0]
		}
		current.VersionConflict = current.VersionConflict || len(current.Versions) > 1
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}
