package sdk_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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

	fy "github.com/cyberspacesec/gxx/v2/fingerYaml"
	"github.com/cyberspacesec/gxx/v2/pkg/network"
	"github.com/cyberspacesec/gxx/v2/sdk"
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
	{"fastjson-exception", "web-alibaba-fastjson", nil, "com.alibaba.fastjson.JSONException: unclosed string", 200, true, ""},
	{"fastjson-parser", "web-alibaba-fastjson", nil, "at com.alibaba.fastjson.parser.DefaultJSONParser.parse() ~[fastjson-1.2.83.jar]", 200, true, "1.2.83"},
	{"fastjson-lexer", "web-alibaba-fastjson", nil, "at com.alibaba.fastjson.parser.JSONLexerBase.scanString() ~[fastjson-1.2.80.jar]", 200, true, "1.2.80"},
	{"fastjson-version-prefix", "web-alibaba-fastjson", nil, "com.alibaba.fastjson.JSONException at fastjson/1.2.83", 500, true, "1.2.83"},
	{"ordinary-javascript", "web-alibaba-fastjson", nil, "<script>var json = JSON.parse(input);</script>", 200, false, ""},
	{"generic-json-error", "web-alibaba-fastjson", nil, "unclosed string", 400, false, ""},
	{"jackson-error", "web-alibaba-fastjson", nil, "com.fasterxml.jackson.core.JsonParseException: unclosed string", 400, false, ""},
	{"gson-error", "web-alibaba-fastjson", nil, "com.google.gson.JsonSyntaxException: unclosed string", 400, false, ""},
	{"generic-fastjson-name", "web-alibaba-fastjson", nil, "fastjson version 1.2.83", 200, false, ""},
	{"generic-client-script", "web-alibaba-fastjson", nil, "<script src='/js/base/fastjson.js'></script>", 200, false, ""},
	{"generic-syntax-error", "web-alibaba-fastjson", nil, "syntax error, expect {, actual error, pos 0", 400, false, ""},
	{"fastjson2-separate-package", "web-alibaba-fastjson", nil, "com.alibaba.fastjson2.JSONException: unclosed string", 400, false, ""},
	{"wordpress-generator", "web-wordpress", nil, `<meta name="generator" content="wordpress 6.8.2">`, 200, true, "6.8.2"},
	{"wordpress-uppercase", "web-wordpress", nil, `<meta name="generator" content="WORDPRESS 6.8">`, 200, true, "6.8"},
	{"wordpress-static-resources", "web-wordpress", nil, `<script src="/wp-includes/app.js"></script><meta name="generator" content="Drupal 10.2.3">`, 200, true, ""},
	{"wordpress-invalid-version", "web-wordpress", nil, `<meta name="generator" content="wordpress unknown">`, 200, true, ""},
	{"wordpress-negative", "web-wordpress", nil, `<meta name="generator" content="Drupal 10.2.3">`, 200, false, ""},
	{"apache-version", "web-apache-http", map[string]string{"Server": "Apache/2.4.62 (Unix)"}, "", 200, true, "2.4.62"},
	{"apache-hidden-version", "web-apache-http", map[string]string{"Server": "Apache"}, "", 200, true, ""},
	{"apache-negative", "web-apache-http", map[string]string{"Server": "nginx/1.26.3"}, "", 200, false, ""},
	{"tomcat-title", "web-apache-tomcat", nil, "<title>Apache Tomcat/9.0.99</title>", 200, true, "9.0.99"},
	{"tomcat-error", "web-apache-tomcat", nil, "<h3>Apache Tomcat/10.1.35</h3>", 404, true, "10.1.35"},
	{"tomcat-coyote-is-not-product-version", "web-apache-tomcat", map[string]string{"Server": "Apache-Coyote/1.1"}, "", 200, true, ""},
	{"tomcat-negative", "web-apache-tomcat", nil, "<title>Application Server/9.0.99</title>", 200, false, ""},
	{"jenkins-headers", "web-jenkins", map[string]string{"X-Jenkins": "2.479.3", "X-Jenkins-Session": "abc"}, "", 200, true, "2.479.3"},
	{"jenkins-agent-protocol", "web-jenkins", nil, "jenkins-agent-protocols", 200, true, ""},
	{"jenkins-other-header", "web-jenkins", map[string]string{"X-Other": "2.479.3"}, "", 200, false, ""},
	{"jenkins-ordinary-page", "web-jenkins", nil, "ordinary page version 2.479.3", 200, false, ""},
	{"nginx-version", "nginx-detect", map[string]string{"Server": "nginx/1.26.3"}, "", 200, true, "1.26.3"},
	{"nginx-hidden-version", "nginx-detect", map[string]string{"Server": "nginx"}, "", 200, true, ""},
	{"nginx-uppercase", "nginx-detect", map[string]string{"Server": "NGINX/1.26.3"}, "", 200, true, "1.26.3"},
	{"nginx-webui-is-not-server", "nginx-detect", map[string]string{"Server": "nginx-webui/1.26.3"}, "", 200, false, ""},
	{"nginx-missing-header", "nginx-detect", nil, "application version 1.26.3", 200, false, ""},
	{"arl-duplicate", "web-arl", nil, "<title>资产灯塔系统</title>", 200, true, ""},
	{"arl-alias", "web-资产灯塔系统", nil, "<title>资产灯塔系统</title>", 200, true, ""},
	{"arl-negative", "web-arl", nil, "<title>普通资产系统</title>", 200, false, ""},
	{"arl-alias-negative", "web-资产灯塔系统", nil, "<title>普通资产系统</title>", 200, false, ""},
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
			if sample.name == "arl-duplicate" {
				count := 0
				for _, product := range result.Products {
					if product.ID == "arl.arl" {
						count++
						if len(product.RuleIDs) != 2 {
							t.Fatalf("ARL 来源丢失: %+v", product)
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
		} else if validation.Status != "sample-tested" || validation.PositiveSamples != positive || validation.NegativeSamples != negative || validation.Method != "synthetic-http-fixtures" || validation.ReviewedAt != "2026-10-01" {
			t.Fatalf("测试记录过期或没有绑定规则内容: %+v", rule.Info)
		}
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
		result.URL = ""
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
	if len(catalog) != len(embedded) || len(catalog) != 2349 {
		t.Fatalf("目录不完整: %d/%d", len(catalog), len(embedded))
	}
	known := map[string]bool{}
	for _, rule := range catalog {
		known[rule.Info.ID] = true
		if len(rule.Info.Source.SHA256) != 64 || len(rule.Detection) == 0 || rule.Info.Source.Version != sdk.Version {
			t.Fatalf("来源或检测依据缺失: %+v", rule)
		}
		if rule.Info.Confidence != nil {
			t.Fatalf("无校准样本却存在置信度: %+v", rule.Info)
		}
		if rule.Info.Product == nil && rule.Info.Vendor != "" {
			t.Fatalf("无产品目录却猜测厂商: %+v", rule.Info)
		}
		if rule.Info.Product == nil && !slices.Contains(rule.MissingMetadata, "product-catalog") {
			t.Fatal("未知产品目录没有质量标记")
		}
		for _, reference := range rule.Info.References {
			if reference == "" || strings.Contains(reference, "example.com") {
				t.Fatalf("占位引用进入结果: %s", reference)
			}
		}
	}
	products, err := sdk.ProductCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, product := range products {
		for _, id := range product.RuleIDs {
			if !known[id] {
				t.Fatalf("目录引用不存在的规则: %s", id)
			}
		}
	}
	for _, verified := range []string{"", "  verified: false\n", "  verified: true\n"} {
		custom := isolatedEngine(t, "id: metadata\ninfo:\n  name: 元数据\n  author: rule-author\n"+verified+"rules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: true\nexpression: r0()\n")
		metadata, err := custom.RuleCatalog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		info := metadata[0].Info
		if info.Vendor != "" || info.Confidence != nil || (info.Verified == nil) != (verified == "") {
			t.Fatalf("未知值或来源声明被替换: %+v", info)
		}
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
