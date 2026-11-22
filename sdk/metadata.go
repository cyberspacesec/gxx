package sdk

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/cyberspacesec/gxx/internal/lifecycle"
	"github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/runner"
)

// Version 是 SDK 源版本，不能作为被识别产品的版本。
const Version = "1.7.0"

type RuleSource struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version,omitempty"`
}

// ProductInfo 是规则命中的产品，来自规则的 info.product 声明，或 WithProductCatalog 对该规则
// 的覆盖；未知厂商、CPE 和分类不从名称自动推断。Identity 为 product 表示命中即确认是这个
// 产品，signal 表示只是技术线索；Assurance 为 verified 表示厂商与产品已确认且有官方参考
// 链接，inferred 表示由规则名称与特征推断。
type ProductInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor,omitempty"`
	Category    string   `json:"category,omitempty"`
	Identity    string   `json:"identity,omitempty"`
	Assurance   string   `json:"assurance,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	CPE         []string `json:"cpe,omitempty"`
	References  []string `json:"references,omitempty"`
	Description string   `json:"description,omitempty"`
}

// ProductDefinition 是产品目录的一项：产品信息与声明它的规则标识。
type ProductDefinition struct {
	ProductInfo
	RuleIDs []string `json:"rule_ids"`
}

// Service 是 TCP/UDP 规则识别的服务，来自规则的 info.services。
type Service struct {
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
	Ports     []int  `json:"ports,omitempty"`
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

// 内置产品目录由 fingerYaml/ 的产品声明生成；规则或声明变化后重新生成，测试断言二者一致。
//
//go:generate go run ../internal/catalog/gen -rules ../fingerYaml -out catalog.json
//go:embed catalog.json
var catalogData []byte

// 专项样本记录绑定规则文件的实际 SHA256，由样本测试执行后写入，见 product_integration_test.go。
//
//go:embed validations.json
var validationData []byte

var catalogOnce sync.Once
var builtinCatalog struct {
	Products    []ProductDefinition
	Validations []RuleAssessment
}
var catalogError error

func loadCatalog() error {
	catalogOnce.Do(func() {
		// 目录错误经 NewEngine 冒泡，与同函数内的校验器保持同一 sentinel，
		// 调用方用 errors.Is(err, ErrInvalidOption) 即可统一判定。
		var products struct {
			Products []ProductDefinition `json:"products"`
		}
		if err := json.Unmarshal(catalogData, &products); err != nil {
			catalogError = fmt.Errorf("%w: 解析产品目录失败: %v", ErrInvalidOption, err)
			return
		}
		if err := json.Unmarshal(validationData, &builtinCatalog.Validations); err != nil {
			catalogError = fmt.Errorf("%w: 解析专项样本记录失败: %v", ErrInvalidOption, err)
			return
		}
		builtinCatalog.Products = products.Products
		if catalogError = validateProductDefinitions(builtinCatalog.Products); catalogError == nil {
			catalogError = validateAssessments(builtinCatalog.Validations)
		}
	})
	return catalogError
}

// ProductCatalog 返回内置产品目录的独立副本，便于系统扩展及导入。目录由内置规则的
// 产品声明生成，每个产品列出声明它的全部规则标识。
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
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
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
		current.MissingMetadata = missingMetadata(current, versionExtractor)
		result[index] = current
	}
	return result, nil
}

// MissingMetadata 的取值，按以下顺序列出，表示尚需补充或核实的数据项，不代表规则失效。
const (
	MissingProduct          = "product"           // 规则没有产品声明，WithProductCatalog 也没有覆盖
	MissingVendor           = "vendor"            // 产品没有厂商
	MissingProductAssurance = "product-assurance" // 产品信息为推断（assurance 不是 verified）
	MissingTags             = "tags"              // 规则与产品都没有标签
	MissingReferences       = "references"        // 规则与产品都没有有效参考链接
	MissingServices         = "services"          // TCP/UDP 规则没有声明识别的服务
	MissingSampleValidation = "sample-validation" // 没有绑定当前规则内容的专项样本记录
	MissingVersionExtractor = "version-extractor" // 没有子规则输出 product_version
)

func missingMetadata(rule RuleMetadata, versionExtractor bool) []string {
	var missing []string
	info := rule.Info
	if info.Product == nil {
		missing = append(missing, MissingProduct)
	} else {
		if info.Product.Vendor == "" {
			missing = append(missing, MissingVendor)
		}
		if info.Product.Assurance != "verified" {
			missing = append(missing, MissingProductAssurance)
		}
	}
	if len(info.Tags) == 0 {
		missing = append(missing, MissingTags)
	}
	if len(info.References) == 0 {
		missing = append(missing, MissingReferences)
	}
	if (rule.Transport == "tcp" || rule.Transport == "udp" || rule.Transport == "mixed" && slices.ContainsFunc(rule.Detection, func(d DetectionRule) bool {
		return d.Transport == "tcp" || d.Transport == "udp"
	})) && len(info.Services) == 0 {
		missing = append(missing, MissingServices)
	}
	if info.Validation.Status == "not-tested" {
		missing = append(missing, MissingSampleValidation)
	}
	if !versionExtractor {
		missing = append(missing, MissingVersionExtractor)
	}
	return missing
}

func (e *Engine) convertFingerInfo(metadata finger.Metadata) FingerInfo {
	info := metadata.Info
	result := FingerInfo{ID: metadata.ID, Name: info.Name, Author: info.Author, Severity: info.Severity,
		Description: info.Description, Tags: splitTags(info.Tags), Created: info.Created,
		References: validReferences(info.Reference), Source: RuleSource{Path: metadata.Source.Path, SHA256: metadata.Source.SHA256},
		VerificationStatus: "unknown", Validation: ValidationInfo{Status: "not-tested"},
		Services: convertServices(info.Services), Metadata: finger.CloneMetadata(info.Metadata)}
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
	if product, exists := e.ruleProduct(metadata.ID, info.Product); exists {
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

// validReferences 去掉空引用、占位链接与重复项，判定规则与规则校验相同。
func validReferences(references []string) []string {
	var result []string
	for _, reference := range references {
		reference = strings.TrimSpace(reference)
		if !finger.ValidReferenceURL(reference) {
			continue
		}
		if !slices.Contains(result, reference) {
			result = append(result, reference)
		}
	}
	return result
}

// catalogOverrides 把 WithProductCatalog 的目录展开为按规则标识的覆盖；同一规则只能
// 出现在一个目录项中，由 validateProductDefinitions 保证。
func catalogOverrides(definitions []ProductDefinition) map[string]ProductInfo {
	overrides := make(map[string]ProductInfo)
	for _, definition := range definitions {
		for _, ruleID := range definition.RuleIDs {
			overrides[ruleID] = cloneProduct(definition.ProductInfo)
		}
	}
	return overrides
}

// ruleProduct 返回规则的产品信息：WithProductCatalog 按规则标识的覆盖优先，否则取规则
// 自带的声明；声明没有产品标识时视为未声明。返回值是独立副本。
func (e *Engine) ruleProduct(ruleID string, declared *finger.Product) (ProductInfo, bool) {
	if product, exists := e.productOverrides[ruleID]; exists {
		return cloneProduct(product), true
	}
	if declared == nil || declared.ID == "" {
		return ProductInfo{}, false
	}
	return declaredProduct(*declared), true
}

// declaredProduct 把规则声明转为产品信息；无效的参考链接与 CPE 不进入结果，与规则引用的处理一致。
func declaredProduct(declared finger.Product) ProductInfo {
	product := ProductInfo{ID: declared.ID, Name: declared.Name, Vendor: declared.Vendor, Category: declared.Category,
		Identity: declared.Identity, Assurance: declared.Assurance, Tags: slices.Clone(declared.Tags),
		Aliases: slices.Clone(declared.Aliases), References: validReferences(declared.References), Description: declared.Description}
	for _, cpe := range declared.CPE {
		if finger.ValidCPE(cpe) {
			product.CPE = append(product.CPE, cpe)
		}
	}
	return product
}

// checkRuleProducts 检查规则集中同一产品标识的有效声明（规则声明叠加目录覆盖后）完全一致，
// 否则产品归并的结果会取决于命中顺序。返回 *ProductConflictError。
func checkRuleProducts(fingers []*finger.Finger, overrides map[string]ProductInfo) error {
	type declaration struct {
		ruleID  string
		product finger.Product
	}
	seen := make(map[string]declaration)
	for _, fg := range fingers {
		var product ProductInfo
		if override, exists := overrides[fg.Id]; exists {
			product = override
		} else if fg.Info.Product != nil && fg.Info.Product.ID != "" {
			product = declaredProduct(*fg.Info.Product)
		} else {
			continue
		}
		current := finger.Product(product)
		first, exists := seen[product.ID]
		if !exists {
			seen[product.ID] = declaration{fg.Id, current}
			continue
		}
		if field := first.product.DifferentField(current); field != "" {
			return &ProductConflictError{ProductID: product.ID, RuleIDs: [2]string{first.ruleID, fg.Id}, Field: field}
		}
	}
	return nil
}

func convertServices(services []finger.Service) []Service {
	if len(services) == 0 {
		return nil
	}
	result := make([]Service, len(services))
	for index, service := range services {
		result[index] = Service{Protocol: service.Protocol, Transport: service.Transport, Ports: slices.Clone(service.Ports)}
	}
	return result
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
	ids, rules := make(map[string]bool), make(map[string]string)
	for _, product := range products {
		if strings.TrimSpace(product.ID) == "" || strings.TrimSpace(product.Name) == "" || len(product.RuleIDs) == 0 {
			return fmt.Errorf("%w: 产品目录需要 ID、名称和规则 ID", ErrInvalidOption)
		}
		if ids[product.ID] {
			return fmt.Errorf("%w: 产品 ID 重复: %s", ErrInvalidOption, product.ID)
		}
		ids[product.ID] = true
		for _, id := range product.RuleIDs {
			if id == "" {
				return fmt.Errorf("%w: 产品 %s 的规则 ID 为空", ErrInvalidOption, product.ID)
			}
			if owner, exists := rules[id]; exists {
				return fmt.Errorf("%w: 规则 %s 同时由产品 %s 与 %s 声明", ErrInvalidOption, id, owner, product.ID)
			}
			rules[id] = product.ID
		}
		for field, value := range map[string]struct {
			value   string
			allowed []string
		}{"category": {product.Category, finger.ProductCategories}, "identity": {product.Identity, finger.ProductIdentities}, "assurance": {product.Assurance, finger.ProductAssurances}} {
			if value.value != "" && !slices.Contains(value.allowed, value.value) {
				return fmt.Errorf("%w: 产品 %s 的 %s 取值无效: %s", ErrInvalidOption, product.ID, field, value.value)
			}
		}
		for _, reference := range product.References {
			if !finger.ValidReferenceURL(reference) {
				return fmt.Errorf("%w: 产品参考链接无效: %s", ErrInvalidOption, reference)
			}
		}
		for _, cpe := range product.CPE {
			if !finger.ValidCPE(cpe) {
				return fmt.Errorf("%w: CPE 格式无效: %s", ErrInvalidOption, cpe)
			}
		}
	}
	return nil
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
