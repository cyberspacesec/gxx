package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	fy "github.com/cyberspacesec/gxx/fingerYaml"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/sdk"
)

type productSample struct {
	name    string
	rule    string
	headers map[string]string
	body    string
	status  int
	hit     bool
	version string
}

// 样本覆盖明确的响应特征与常见相似内容，不代表真实产品部署的准确率。
var productSamples = []productSample{
	{"fastjson-exception", "alibaba-fastjson", nil, "com.alibaba.fastjson.JSONException: unclosed string", 200, true, ""},
	{"fastjson-parser", "alibaba-fastjson", nil, "at com.alibaba.fastjson.parser.DefaultJSONParser.parse() ~[fastjson-1.2.83.jar]", 200, true, "1.2.83"},
	{"fastjson-lexer", "alibaba-fastjson", nil, "at com.alibaba.fastjson.parser.JSONLexerBase.scanString() ~[fastjson-1.2.80.jar]", 200, true, "1.2.80"},
	{"fastjson-version-prefix", "alibaba-fastjson", nil, "com.alibaba.fastjson.JSONException at fastjson/1.2.83", 500, true, "1.2.83"},
	{"ordinary-javascript", "alibaba-fastjson", nil, "<script>var json = JSON.parse(input);</script>", 200, false, ""},
	{"generic-json-error", "alibaba-fastjson", nil, "unclosed string", 400, false, ""},
	{"jackson-error", "alibaba-fastjson", nil, "com.fasterxml.jackson.core.JsonParseException: unclosed string", 400, false, ""},
	{"gson-error", "alibaba-fastjson", nil, "com.google.gson.JsonSyntaxException: unclosed string", 400, false, ""},
	{"generic-fastjson-name", "alibaba-fastjson", nil, "fastjson version 1.2.83", 200, false, ""},
	{"generic-client-script", "alibaba-fastjson", nil, "<script src='/js/base/fastjson.js'></script>", 200, false, ""},
	{"generic-syntax-error", "alibaba-fastjson", nil, "syntax error, expect {, actual error, pos 0", 400, false, ""},
	{"fastjson2-separate-package", "alibaba-fastjson", nil, "com.alibaba.fastjson2.JSONException: unclosed string", 400, false, ""},
	{"wordpress-generator", "wordpress", nil, `<meta name="generator" content="wordpress 6.8.2">`, 200, true, "6.8.2"},
	{"wordpress-uppercase", "wordpress", nil, `<meta name="generator" content="WORDPRESS 6.8">`, 200, true, "6.8"},
	{"wordpress-static-resources", "wordpress", nil, `<script src="/wp-includes/app.js"></script><meta name="generator" content="Drupal 10.2.3">`, 200, true, ""},
	{"wordpress-invalid-version", "wordpress", nil, `<meta name="generator" content="wordpress unknown">`, 200, true, ""},
	{"wordpress-negative", "wordpress", nil, `<meta name="generator" content="Drupal 10.2.3">`, 200, false, ""},
	{"apache-version", "apache-http-server", map[string]string{"Server": "Apache/2.4.62 (Unix)"}, "", 200, true, "2.4.62"},
	{"apache-hidden-version", "apache-http-server", map[string]string{"Server": "Apache"}, "", 200, true, ""},
	{"apache-negative", "apache-http-server", map[string]string{"Server": "nginx/1.26.3"}, "", 200, false, ""},
	{"tomcat-title", "apache-tomcat", nil, "<title>Apache Tomcat/9.0.99</title>", 200, true, "9.0.99"},
	{"tomcat-error", "apache-tomcat", nil, "<h3>Apache Tomcat/10.1.35</h3>", 404, true, "10.1.35"},
	{"tomcat-coyote-is-not-product-version", "apache-tomcat", map[string]string{"Server": "Apache-Coyote/1.1"}, "", 200, true, ""},
	{"tomcat-negative", "apache-tomcat", nil, "<title>Application Server/9.0.99</title>", 200, false, ""},
	{"jenkins-headers", "jenkins", map[string]string{"X-Jenkins": "2.479.3", "X-Jenkins-Session": "abc"}, "", 200, true, "2.479.3"},
	{"jenkins-agent-protocol", "jenkins", nil, "jenkins-agent-protocols", 200, true, ""},
	{"jenkins-other-header", "jenkins", map[string]string{"X-Other": "2.479.3"}, "", 200, false, ""},
	{"jenkins-ordinary-page", "jenkins", nil, "ordinary page version 2.479.3", 200, false, ""},
	{"nginx-version", "nginx", map[string]string{"Server": "nginx/1.26.3"}, "", 200, true, "1.26.3"},
	{"nginx-hidden-version", "nginx", map[string]string{"Server": "nginx"}, "", 200, true, ""},
	{"nginx-uppercase", "nginx", map[string]string{"Server": "NGINX/1.26.3"}, "", 200, true, "1.26.3"},
	{"nginx-webui-is-not-server", "nginx", map[string]string{"Server": "nginx-webui/1.26.3"}, "", 200, false, ""},
	{"nginx-missing-header", "nginx", nil, "application version 1.26.3", 200, false, ""},
	{"arl-title", "arl", nil, "<title>资产灯塔系统</title>", 200, true, ""},
	{"arl-negative", "arl", nil, "<title>普通资产系统</title>", 200, false, ""},
}

// 专项样本记录的方法与适用范围。
const (
	sampleMethod = "synthetic-http-fixtures"
	sampleScope  = "受控 HTTP 响应的特征匹配与阴性排除；不代表真实产品准确率。"
)

var updateValidations = flag.Bool("update-validations", false, "样本全部通过后，按本次实际加载的规则摘要重写 validations.json")

// writeValidations 在样本全部通过后写入专项样本记录：每条有样本的规则记录本次实际加载的
// 规则文件 SHA256、阳性与阴性样本数及执行日期，不沿用旧记录。
func writeValidations(t *testing.T, metadata []sdk.RuleMetadata) {
	t.Helper()
	if t.Failed() {
		t.Fatal("样本没有全部通过，不更新专项样本记录")
	}
	counts := make(map[string][2]int)
	for _, sample := range productSamples {
		count := counts[sample.rule]
		if sample.hit {
			count[0]++
		} else {
			count[1]++
		}
		counts[sample.rule] = count
	}
	var records []sdk.RuleAssessment
	for _, rule := range metadata {
		count, sampled := counts[rule.Info.ID]
		if !sampled {
			continue
		}
		records = append(records, sdk.RuleAssessment{RuleID: rule.Info.ID, RuleSHA256: rule.Info.Source.SHA256, Validation: sdk.ValidationInfo{
			Status: "sample-tested", Method: sampleMethod, PositiveSamples: count[0], NegativeSamples: count[1],
			ReviewedAt: time.Now().Format(time.DateOnly), Scope: sampleScope}})
	}
	if len(records) != len(counts) {
		t.Fatalf("样本引用了不存在的规则: %d/%d", len(records), len(counts))
	}
	slices.SortFunc(records, func(a, b sdk.RuleAssessment) int { return strings.Compare(a.RuleID, b.RuleID) })
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(records); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("validations.json", buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("已写入 %d 条专项样本记录", len(records))
}

func TestFullCorpusProductSamples(t *testing.T) {
	var current atomic.Pointer[productSample]
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		sample := current.Load()
		if sample == nil {
			http.NotFound(w, r)
			return
		}
		for key, value := range sample.headers {
			w.Header().Set(key, value)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(sample.status)
		fmt.Fprint(w, sample.body)
	}))
	defer server.Close()
	e, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for index := range productSamples {
		sample := &productSamples[index]
		t.Run(sample.name, func(t *testing.T) {
			current.Store(sample)
			result, err := e.Scan(context.Background(), server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var found *sdk.FingerMatch
			for index := range result.Matches {
				if result.Matches[index].Info.ID == sample.rule {
					found = &result.Matches[index]
				}
			}
			if (found != nil) != sample.hit {
				t.Fatalf("rule=%s expected=%v matches=%+v", sample.rule, sample.hit, result.Matches)
			}
			if found == nil {
				return
			}
			if found.ProductVersion != sample.version {
				t.Fatalf("产品版本串用或提取失败: got=%q want=%q details=%+v", found.ProductVersion, sample.version, found.MatchedRules)
			}
			if found.Info.Author == found.Info.Vendor && found.Info.Vendor != "" {
				t.Fatal("规则作者写入厂商")
			}
			if found.Info.Confidence != nil {
				t.Fatal("合成样本被赋予实际准确率")
			}
			if len(found.MatchedRules) == 0 {
				t.Fatal("命中子规则没有回传")
			}
			// 正文与表达式完全相同的两条 ARL 规则已合并为一条，产品只有这一个来源。
			if sample.name == "arl-title" {
				count := 0
				for _, product := range result.Products {
					if product.ID == "arl.arl" {
						count++
						if len(product.RuleIDs) != 1 || product.RuleIDs[0] != "arl" || !slices.Contains(product.Aliases, "资产灯塔系统") {
							t.Fatalf("ARL 来源不符: %+v", product)
						}
					}
				}
				if count != 1 {
					t.Fatalf("ARL 产品归并失败: %+v", result.Products)
				}
			}
		})
	}
	metadata, err := e.RuleCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range metadata {
		positive, negative := 0, 0
		for _, sample := range productSamples {
			if sample.rule == rule.Info.ID {
				if sample.hit {
					positive++
				} else {
					negative++
				}
			}
		}
		validation := rule.Info.Validation
		if positive+negative == 0 {
			if validation.Status != "not-tested" {
				t.Fatalf("未执行定向样本的规则被标记为已测试: %+v", rule.Info)
			}
		} else if _, err := time.Parse(time.DateOnly, validation.ReviewedAt); validation.Status != "sample-tested" || validation.PositiveSamples != positive || validation.NegativeSamples != negative || validation.Method != sampleMethod || validation.Scope != sampleScope || err != nil {
			if !*updateValidations {
				t.Fatalf("测试记录过期或没有绑定规则内容（规则变化后执行 go test ./sdk -run TestFullCorpusProductSamples -update-validations）: %+v", rule.Info)
			}
		}
	}
	if *updateValidations {
		writeValidations(t, metadata)
	}
	stats := e.PoolStats()
	if stats.CompletedTasks != int64(len(productSamples)*e.FingerCount()) {
		t.Fatalf("没有执行全量指纹: %+v", stats)
	}
	t.Logf("全量规则=%d 样本=%d 执行任务=%d HTTP请求=%d", e.FingerCount(), len(productSamples), stats.CompletedTasks, requests.Load())
}

func TestMatchDetailsPreservesFullCorpusResults(t *testing.T) {
	var results []*sdk.TargetResult
	for _, details := range []bool{true, false} {
		e, target := fullRuleFixture(t, 256<<10, sdk.WithMatchDetails(details))
		result, err := e.Scan(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		for index := range result.Matches {
			match := &result.Matches[index]
			if details && len(match.MatchedRules) == 0 {
				t.Fatal("命中详情缺失")
			}
			if !details && len(match.MatchedRules) != 0 {
				t.Fatal("关闭详情后仍采集证据")
			}
			match.MatchedRules = nil
		}
		slices.SortFunc(result.Matches, func(a, b sdk.FingerMatch) int { return strings.Compare(a.Info.ID, b.Info.ID) })
		result.URL, result.FinalURL, result.Headers = "", "", ""
		results = append(results, result)
	}
	a, _ := json.Marshal(results[0])
	b, _ := json.Marshal(results[1])
	if string(a) != string(b) {
		t.Fatalf("详情开关改变了识别结果或版本: %s != %s", a, b)
	}
}

func TestOutputOnlyComesFromSuccessfulRuleAndExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ordinary body") }))
	defer server.Close()
	for _, details := range []bool{true, false} {
		yaml := "id: output-test\ninfo:\n  name: 输出测试\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: false\n    output:\n      product_version: '\"99.0\"'\n  r1:\n    request:\n      method: GET\n      path: /\n    expression: true\n    output:\n      product_version: '\"[\".bsubmatch(response.body)[\"version\"]'\nexpression: r0() || r1()\n"
		e := isolatedEngine(t, yaml, sdk.WithMatchDetails(details))
		result, err := e.Scan(context.Background(), server.URL)
		if err != nil || len(result.Matches) != 1 {
			t.Fatalf("%v %v", result, err)
		}
		match := result.Matches[0]
		if match.ProductVersion != "" || len(match.ProductVersions) > 0 {
			t.Fatalf("失败或未命中的输出成为版本: %+v", match)
		}
		if details && (len(match.MatchedRules) != 1 || match.MatchedRules[0].Key != "r1") {
			t.Fatalf("未命中子规则被回传: %+v", match)
		}
		if !details && len(match.MatchedRules) > 0 {
			t.Fatal("关闭详情后仍采集证据")
		}
	}
}

func TestVersionConflictIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer server.Close()
	yaml := "id: conflict\ninfo:\n  name: 版本冲突\nrules:\n"
	for index, version := range []string{"1.0", "2.0"} {
		yaml += fmt.Sprintf("  r%d:\n    request:\n      method: GET\n      path: /\n    expression: true\n    output:\n      product_version: '\"%s\"'\n", index, version)
	}
	yaml += "expression: r0() && r1()\n"
	e := isolatedEngine(t, yaml, sdk.WithMatchDetails(false))
	result, err := e.Scan(context.Background(), server.URL)
	if err != nil || len(result.Matches) != 1 {
		t.Fatalf("%v %v", result, err)
	}
	match := result.Matches[0]
	if !match.VersionConflict || match.ProductVersion != "" || len(match.ProductVersions) != 2 || len(result.Products) != 1 || !result.Products[0].VersionConflict {
		t.Fatalf("版本冲突被隐藏: %+v", result)
	}
}

func TestMatchDetailBudgetPreservesDetectionAndVersionConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer server.Close()
	yaml := "id: bounded\ninfo:\n  name: 详情预算\nrules:\n"
	for index := 0; index < 70; index++ {
		yaml += fmt.Sprintf("  r%d:\n    request:\n      method: GET\n      path: /\n    expression: true\n    output:\n      product_version: '\"1.%d\"'\n", index, index)
	}
	yaml += "expression: r0()\n"
	e := isolatedEngine(t, yaml)
	result, err := e.Scan(context.Background(), server.URL)
	if err != nil || len(result.Matches) != 1 {
		t.Fatalf("%v %v", result, err)
	}
	match := result.Matches[0]
	if len(match.MatchedRules) != 64 || !match.DetailsTruncated || len(match.ProductVersions) != 16 || !match.VersionConflict || match.ProductVersion != "" {
		t.Fatalf("预算改变了识别或隐瞒了版本冲突: %+v", match)
	}
}

func TestRuleCatalogUsesActualRequestTransports(t *testing.T) {
	e := isolatedEngine(t, "id: transport\ninfo:\n  name: 协议目录\nrules:\n  r0:\n    request:\n      type: tcp\n    expression: true\n  r1:\n    request:\n      method: GET\n      path: /\n    expression: true\nexpression: r0() || r1()\n")
	catalog, err := e.RuleCatalog(context.Background())
	if err != nil || catalog[0].Transport != "mixed" || catalog[0].Detection[0].Transport != "tcp" || catalog[0].Detection[1].Transport != "http" {
		t.Fatalf("请求协议被统一当成 HTTP: %+v %v", catalog, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.RuleCatalog(ctx); err == nil {
		t.Fatal("规则目录忽略 context 取消")
	}
}

func TestEvidenceResultDoesNotRetainResponseBody(t *testing.T) {
	position := int(network.MaxDefaultBody) - 1024
	body := strings.Repeat("x", position) + "marker" + strings.Repeat("y", 512)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer server.Close()
	e := engine(t, "  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'marker')\n")
	result, err := e.Scan(context.Background(), server.URL)
	if err != nil || len(result.Matches) != 1 {
		t.Fatalf("%v %v", result, err)
	}
	evidence := result.Matches[0].MatchedRules[0].Evidence
	if len(evidence) != 1 || evidence[0].Start != position || evidence[0].End != position+len("marker") || len(evidence[0].Snippet) > 256 {
		t.Fatalf("证据位置或边界错误: %+v", evidence)
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 8192 {
		t.Fatalf("扫描结果带回响应体: size=%d error=%v", len(encoded), err)
	}
}

func TestRuleCatalogCoversEntireCorpusAndSeparatesUnknownMetadata(t *testing.T) {
	e, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	catalog, err := e.RuleCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := fy.GetEmbeddedFingerYaml()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != len(embedded) || len(catalog) != 2348 {
		t.Fatalf("目录不完整: %d/%d", len(catalog), len(embedded))
	}
	products, err := sdk.ProductCatalog()
	if err != nil {
		t.Fatal(err)
	}
	owner := map[string]sdk.ProductDefinition{}
	for _, product := range products {
		for _, id := range product.RuleIDs {
			owner[id] = product
		}
	}
	for _, rule := range catalog {
		if len(rule.Info.Source.SHA256) != 64 || len(rule.Detection) == 0 || rule.Info.Source.Version != sdk.Version {
			t.Fatalf("来源或检测依据缺失: %+v", rule)
		}
		if rule.Info.Confidence != nil {
			t.Fatalf("无校准样本却存在置信度: %+v", rule.Info)
		}
		// 每条内置规则都声明产品，产品信息与内置产品目录一致；厂商只来自产品声明。
		product := rule.Info.Product
		definition, listed := owner[rule.Info.ID]
		if product == nil || !listed || product.ID != definition.ID || product.Name != definition.Name || product.Identity == "" || product.Assurance == "" {
			t.Fatalf("产品声明缺失或与目录不一致: %+v %+v", rule.Info, definition)
		}
		if rule.Info.Vendor != product.Vendor || slices.Contains(rule.MissingMetadata, sdk.MissingProduct) {
			t.Fatalf("厂商或缺项不符: %+v %v", rule.Info, rule.MissingMetadata)
		}
		if slices.Contains(rule.MissingMetadata, sdk.MissingVendor) != (product.Vendor == "") ||
			slices.Contains(rule.MissingMetadata, sdk.MissingProductAssurance) != (product.Assurance != "verified") ||
			slices.Contains(rule.MissingMetadata, sdk.MissingReferences) != (len(rule.Info.References) == 0) {
			t.Fatalf("缺项与产品信息不符: %+v %v", rule.Info, rule.MissingMetadata)
		}
		if product.Assurance == "verified" && len(product.References) == 0 {
			t.Fatalf("verified 产品没有参考链接: %+v", product)
		}
		for _, reference := range rule.Info.References {
			if reference == "" || strings.Contains(reference, "example.com") {
				t.Fatalf("占位引用进入结果: %s", reference)
			}
		}
	}
	if len(owner) != len(catalog) {
		t.Fatalf("产品目录与规则不一一对应: %d/%d", len(owner), len(catalog))
	}
	// 调用方自有规则可以不声明产品：产品为空，不猜测厂商，缺项标记 product。
	for _, verified := range []string{"", "  verified: false\n", "  verified: true\n"} {
		custom := isolatedEngine(t, "id: metadata\ninfo:\n  name: 元数据\n  author: rule-author\n"+verified+"rules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: true\nexpression: r0()\n")
		metadata, err := custom.RuleCatalog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		info := metadata[0].Info
		if info.Vendor != "" || info.Product != nil || info.Confidence != nil || (info.Verified == nil) != (verified == "") || !slices.Contains(metadata[0].MissingMetadata, sdk.MissingProduct) {
			t.Fatalf("未知值或来源声明被替换: %+v %v", info, metadata[0].MissingMetadata)
		}
	}
}

// 规则自带的产品、服务与附加元数据声明原样进入结果与规则目录；TCP 规则缺少服务声明时标记缺项。
func TestDeclaredProductServicesAndMetadata(t *testing.T) {
	yaml := "id: declared\ninfo:\n  name: 声明\n  author: rule-author\n  tags: login\n  product:\n    id: acme.portal\n    name: Acme Portal\n    vendor: Acme\n    category: application\n    identity: product\n    assurance: verified\n    tags: [portal]\n    aliases: [门户]\n    cpe: ['cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*', 'not-a-cpe']\n    references: [https://acme.test/, https://example.com/]\n    description: 门户\n  services:\n    - protocol: http\n      transport: tcp\n      ports: [80, 443]\n  metadata:\n    owner: {team: a}\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'marker')\nexpression: r0()\n"
	e := isolatedEngine(t, yaml)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "marker") }))
	defer server.Close()
	result, err := e.Scan(context.Background(), server.URL)
	if err != nil || len(result.Matches) != 1 || len(result.Products) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	info := result.Matches[0].Info
	want := sdk.ProductInfo{ID: "acme.portal", Name: "Acme Portal", Vendor: "Acme", Category: "application", Identity: "product", Assurance: "verified",
		Tags: []string{"portal"}, Aliases: []string{"门户"}, CPE: []string{"cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*"}, References: []string{"https://acme.test/"}, Description: "门户"}
	encode := func(value any) string { data, _ := json.Marshal(value); return string(data) }
	if info.Product == nil || encode(*info.Product) != encode(want) || encode(result.Products[0].ProductInfo) != encode(want) || info.Vendor != "Acme" {
		t.Fatalf("产品声明不符: %+v", info.Product)
	}
	if fmt.Sprint(info.Tags) != "[login portal]" || fmt.Sprint(info.References) != "[https://acme.test/]" {
		t.Fatalf("规则与产品的标签、引用合并不符: %v %v", info.Tags, info.References)
	}
	if encode(info.Services) != `[{"protocol":"http","transport":"tcp","ports":[80,443]}]` || encode(info.Metadata) != `{"owner":{"team":"a"}}` {
		t.Fatalf("服务或附加元数据不符: %s %s", encode(info.Services), encode(info.Metadata))
	}
	info.Product.Tags[0], info.Services[0].Ports[0] = "changed", 1
	info.Metadata["owner"].(map[string]any)["team"] = "changed"
	again, _ := e.Scan(context.Background(), server.URL)
	if second := again.Matches[0].Info; second.Product.Tags[0] != "portal" || second.Services[0].Ports[0] != 80 || second.Metadata["owner"].(map[string]any)["team"] != "a" {
		t.Fatalf("返回值与规则共享了可变数据: %+v", second)
	}
	catalog, err := e.RuleCatalog(context.Background())
	if err != nil || encode(catalog[0].Info.Product) != encode(want) || len(catalog[0].Info.Services) != 1 || slices.Contains(catalog[0].MissingMetadata, sdk.MissingServices) {
		t.Fatalf("规则目录不符: %+v %v", catalog, err)
	}
	tcp := isolatedEngine(t, "id: tcp-rule\ninfo:\n  name: tcp\nrules:\n  r0:\n    request:\n      type: tcp\n      host: 127.0.0.1:22\n    expression: response.raw.bcontains(b'SSH-')\nexpression: r0()\n")
	catalog, err = tcp.RuleCatalog(context.Background())
	if err != nil || !slices.Contains(catalog[0].MissingMetadata, sdk.MissingServices) || !slices.Contains(catalog[0].MissingMetadata, sdk.MissingProduct) {
		t.Fatalf("TCP 规则缺少服务声明应标记: %+v %v", catalog, err)
	}
}

// WithProductCatalog 按规则标识追加或覆盖产品声明；同一产品的有效声明必须一致，同一规则
// 不能被两个目录项声明。
func TestProductCatalogOverridesByRule(t *testing.T) {
	builtin, err := sdk.ProductCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var apache sdk.ProductDefinition
	for _, product := range builtin {
		if product.ID == "apache.http-server" {
			apache = product
		}
	}
	if len(apache.RuleIDs) < 2 {
		t.Fatalf("内置目录中 Apache HTTP Server 应有多条规则: %+v", apache)
	}
	productOf := func(e *sdk.Engine) map[string]*sdk.ProductInfo {
		catalog, err := e.RuleCatalog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		result := make(map[string]*sdk.ProductInfo, len(catalog))
		for _, rule := range catalog {
			result[rule.Info.ID] = rule.Info.Product
		}
		return result
	}
	// 只覆盖同一产品的一条规则会让该产品的声明不一致，加载失败。
	renamed := apache
	renamed.Name, renamed.RuleIDs = "目录名称", apache.RuleIDs[:1]
	_, err = sdk.NewEngine(context.Background(), sdk.WithProductCatalog([]sdk.ProductDefinition{renamed}))
	var conflict *sdk.ProductConflictError
	if !errors.As(err, &conflict) || conflict.ProductID != "apache.http-server" || conflict.Field != "name" || !errors.Is(err, sdk.ErrEngineNotReady) {
		t.Fatalf("同一产品的声明不一致应拒绝加载: %v", err)
	}
	// 覆盖该产品的全部规则：这些规则都使用目录中的信息，其余规则不变。
	renamed.RuleIDs = apache.RuleIDs
	e, err := sdk.NewEngine(context.Background(), sdk.WithProductCatalog([]sdk.ProductDefinition{renamed}))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	products := productOf(e)
	for _, id := range apache.RuleIDs {
		if products[id] == nil || products[id].Name != "目录名称" {
			t.Fatalf("%s 没有使用目录覆盖: %+v", id, products[id])
		}
	}
	if products["wordpress"] == nil || products["wordpress"].ID != "wordpress.wordpress" || products["wordpress"].Name != "WordPress" {
		t.Fatalf("未覆盖的规则应保留自带声明: %+v", products["wordpress"])
	}
	// 把一条规则改归到新的产品标识，只影响这条规则。
	moved := sdk.ProductDefinition{ProductInfo: sdk.ProductInfo{ID: "system.wordpress", Name: "系统产品"}, RuleIDs: []string{"wordpress"}}
	e2, err := sdk.NewEngine(context.Background(), sdk.WithProductCatalog([]sdk.ProductDefinition{moved}))
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if products := productOf(e2); products["wordpress"].ID != "system.wordpress" || products["apache-http-server"].ID != "apache.http-server" {
		t.Fatalf("按规则覆盖不符: %+v %+v", products["wordpress"], products["apache-http-server"])
	}
	// 同一规则被两个目录项声明时报错。
	twice := []sdk.ProductDefinition{moved, {ProductInfo: sdk.ProductInfo{ID: "other.product", Name: "另一产品"}, RuleIDs: []string{"wordpress"}}}
	if _, err := sdk.NewEngine(context.Background(), sdk.WithProductCatalog(twice)); !errors.Is(err, sdk.ErrInvalidOption) || !strings.Contains(err.Error(), "wordpress") {
		t.Fatalf("同一规则被两个目录项声明应报错: %v", err)
	}
	// 自有规则之间同一产品的声明不一致同样拒绝加载，重新加载失败时保留原规则集。
	declare := func(id, name string) string {
		return "id: " + id + "\ninfo:\n  name: " + id + "\n  product:\n    id: acme.portal\n    name: " + name + "\n    category: application\n    identity: product\n    assurance: inferred\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: 'true'\nexpression: r0()\n"
	}
	if _, err := sdk.NewEngine(context.Background(), sdk.WithRuleFS(fstest.MapFS{"a.yaml": {Data: []byte(declare("rule-a", "Portal"))}, "b.yaml": {Data: []byte(declare("rule-b", "Other"))}}, ".")); !errors.As(err, &conflict) {
		t.Fatalf("自有规则的产品声明不一致应拒绝加载: %v", err)
	}
	custom := isolatedEngine(t, declare("rule-a", "Portal"))
	dir := t.TempDir()
	for name, content := range map[string]string{"a.yaml": declare("rule-a", "Portal"), "b.yaml": declare("rule-b", "Other")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := custom.LoadFingerOptions(sdk.FingerOptions{PocFile: dir}); !errors.As(err, &conflict) || !errors.Is(err, sdk.ErrLoadFinger) || custom.FingerCount() != 1 {
		t.Fatalf("重新加载时声明不一致应失败并保留原规则集: %v count=%d", err, custom.FingerCount())
	}
}

func TestCatalogAndAssessmentAreInstanceOwned(t *testing.T) {
	yaml := "id: identity\ninfo:\n  name: 规则名称\n  author: rule-author\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.body.bcontains(b'marker')\nexpression: r0()\n"
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(yaml)))
	confidence := 0.8
	definitions := []sdk.ProductDefinition{{ProductInfo: sdk.ProductInfo{ID: "system.product", Name: "产品名称", Vendor: "产品厂商", Tags: []string{"application"}}, RuleIDs: []string{"identity"}}}
	assessments := []sdk.RuleAssessment{{RuleID: "identity", RuleSHA256: sha, Confidence: &confidence, Validation: sdk.ValidationInfo{Status: "sample-tested", Method: "external-calibration", PositiveSamples: 8, NegativeSamples: 2, Scope: "独立固定样本集"}}}
	productOption, assessmentOption := sdk.WithProductCatalog(definitions), sdk.WithRuleAssessments(assessments)
	definitions[0].Vendor = "caller-mutated"
	definitions[0].Tags[0] = "caller-mutated"
	confidence = 0.1
	a := isolatedEngine(t, yaml, productOption, assessmentOption, sdk.WithRuleSourceVersion("rules-2026-10-01"))
	b := isolatedEngine(t, yaml, sdk.WithProductCatalog([]sdk.ProductDefinition{{ProductInfo: sdk.ProductInfo{ID: "second.product", Name: "第二产品", Vendor: "第二厂商"}, RuleIDs: []string{"identity"}}}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "marker") }))
	defer server.Close()
	var group sync.WaitGroup
	for _, e := range []*sdk.Engine{a, b} {
		group.Add(1)
		go func(e *sdk.Engine) {
			defer group.Done()
			for iteration := 0; iteration < 10; iteration++ {
				result, err := e.Scan(context.Background(), server.URL)
				if err != nil || len(result.Matches) != 1 {
					t.Errorf("%v %v", result, err)
					return
				}
				info := result.Matches[0].Info
				if e == a {
					if info.Vendor != "产品厂商" || info.Product.Tags[0] != "application" || info.Confidence == nil || *info.Confidence != 0.8 || info.Source.Version != "rules-2026-10-01" {
						t.Errorf("首实例被修改: %+v", info)
						return
					}
					info.Product.Tags[0] = "result-mutated"
					*info.Confidence = 0.2
				} else if info.Vendor != "第二厂商" || info.Confidence != nil {
					t.Errorf("第二实例被覆盖: %+v", info)
					return
				}
			}
		}(e)
	}
	group.Wait()
	path := filepath.Join(t.TempDir(), "changed.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(yaml, "rule-author", "another-author", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadFingerOptions(sdk.FingerOptions{PocYaml: path}); err != nil {
		t.Fatal(err)
	}
	catalog, err := a.RuleCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if catalog[0].Info.Confidence != nil || catalog[0].Info.Validation.Status != "not-tested" {
		t.Fatal("内容变化后仍沿用旧测试记录")
	}
}
