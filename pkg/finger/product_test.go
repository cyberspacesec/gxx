package finger

import (
	"encoding/json"
	"errors"
	"testing"
)

const productRule = `id: weaver-e-cology
info:
  name: 泛微 e-cology
  author: tester
  product:
    id: weaver.e-cology
    name: e-cology
    vendor: 泛微网络
    category: application
    identity: product
    assurance: verified
    tags: [oa]
    aliases: [泛微OA, ecology]
    references:
      - https://www.weaver.com.cn/
    description: 协同办公平台
  services:
    - protocol: ssh
      transport: tcp
      ports: [22, 2222]
  metadata:
    owner: team-a
    nested:
      1: one
      list: [a, {b: c}]
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body.ibcontains(b"ecology")
expression: r0()
`

func TestInfoParsesProductServicesAndMetadata(t *testing.T) {
	fg, err := Parse([]byte(productRule), "rule.yaml")
	if err != nil {
		t.Fatal(err)
	}
	product := fg.Info.Product
	want := Product{ID: "weaver.e-cology", Name: "e-cology", Vendor: "泛微网络", Category: "application", Identity: "product",
		Assurance: "verified", Tags: []string{"oa"}, Aliases: []string{"泛微OA", "ecology"}, References: []string{"https://www.weaver.com.cn/"},
		Description: "协同办公平台"}
	if product == nil || !product.Equal(want) {
		t.Fatalf("产品声明解析错误: %+v", product)
	}
	if len(fg.Info.Services) != 1 || fg.Info.Services[0].Protocol != "ssh" || fg.Info.Services[0].Transport != "tcp" || len(fg.Info.Services[0].Ports) != 2 {
		t.Fatalf("服务声明解析错误: %+v", fg.Info.Services)
	}
	// 附加元数据的嵌套映射统一为 map[string]any，可以直接编码为 JSON。
	encoded, err := json.Marshal(fg.Info.Metadata)
	if err != nil {
		t.Fatalf("附加元数据无法编码为 JSON: %v", err)
	}
	if string(encoded) != `{"nested":{"1":"one","list":["a",{"b":"c"}]},"owner":"team-a"}` {
		t.Fatalf("附加元数据被改变: %s", encoded)
	}
	clone := CloneMetadata(fg.Info.Metadata)
	clone["nested"].(map[string]any)["list"].([]any)[1].(map[string]any)["b"] = "changed"
	if fg.Info.Metadata["nested"].(map[string]any)["list"].([]any)[1].(map[string]any)["b"] != "c" {
		t.Fatal("附加元数据的副本与原值共享")
	}
	services := CloneServices(fg.Info.Services)
	services[0].Ports[0] = 1
	copied := product.Clone()
	copied.Tags[0] = "changed"
	if fg.Info.Services[0].Ports[0] != 22 || product.Tags[0] != "oa" {
		t.Fatal("服务或产品声明的副本与原值共享")
	}

	plain, err := Parse([]byte("id: plain\ninfo:\n  name: plain\nrules:\n  r0:\n    expression: 'true'\nexpression: r0()\n"), "plain.yaml")
	if err != nil || plain.Info.Product != nil || plain.Info.Services != nil || plain.Info.Metadata != nil {
		t.Fatalf("未声明时应为空: %+v %v", plain.Info, err)
	}
	// 类型不符的声明是 YAML 结构错误，规则无法加载。
	for _, broken := range []string{"  product: weaver\n", "  services: ssh\n", "  metadata: [a]\n", "  services:\n    - ports: [abc]\n"} {
		content := "id: broken\ninfo:\n  name: broken\n" + broken + "rules:\n  r0:\n    expression: 'true'\nexpression: r0()\n"
		if _, err := Parse([]byte(content), ""); err == nil {
			t.Fatalf("类型不符的声明应解析失败: %q", broken)
		}
	}
}

func TestCheckProductDeclarations(t *testing.T) {
	base := Product{ID: "acme.portal", Name: "Portal", Category: "application", Identity: "product", Assurance: "inferred", Tags: []string{"oa"}}
	rule := func(id string, product *Product) *Finger { return &Finger{Id: id, Info: Info{Product: product}} }
	same := base.Clone()
	same.Tags = append([]string(nil), base.Tags...)
	if err := CheckProductDeclarations([]*Finger{rule("a", &base), rule("b", &same), rule("c", nil), rule("d", &Product{})}); err != nil {
		t.Fatalf("相同声明不应报错: %v", err)
	}
	empty := base.Clone()
	empty.Aliases = []string{}
	if err := CheckProductDeclarations([]*Finger{rule("a", &base), rule("b", &empty)}); err != nil {
		t.Fatalf("空列表与未填写应视为相同: %v", err)
	}
	for field, mutate := range map[string]func(*Product){
		"name":        func(p *Product) { p.Name = "Other" },
		"vendor":      func(p *Product) { p.Vendor = "Acme" },
		"category":    func(p *Product) { p.Category = "cms" },
		"identity":    func(p *Product) { p.Identity = "signal" },
		"assurance":   func(p *Product) { p.Assurance = "verified" },
		"tags":        func(p *Product) { p.Tags = []string{"erp"} },
		"aliases":     func(p *Product) { p.Aliases = []string{"门户"} },
		"cpe":         func(p *Product) { p.CPE = []string{"cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*"} },
		"references":  func(p *Product) { p.References = []string{"https://acme.test/"} },
		"description": func(p *Product) { p.Description = "门户" },
	} {
		changed := base.Clone()
		mutate(&changed)
		err := CheckProductDeclarations([]*Finger{rule("first", &base), rule("other", nil), rule("second", &changed)})
		var conflict *ProductConflictError
		if !errors.As(err, &conflict) || conflict.ProductID != "acme.portal" || conflict.RuleIDs != [2]string{"first", "second"} || conflict.Field != field {
			t.Fatalf("%s 不一致应报错: %v", field, err)
		}
	}
}

func TestValidCPEAndReferenceURL(t *testing.T) {
	for _, cpe := range []string{`cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*`} {
		if !ValidCPE(cpe) {
			t.Fatalf("合法 CPE 结构被拒绝: %s", cpe)
		}
	}
	for _, cpe := range []string{`cpe:2.3:a:vendor:product:*`, `cpe:2.3:x:vendor:product:*:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:`,
		`cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:\`, `cpe:2.3:a:vendor:pro duct:*:*:*:*:*:*:*:*`, `cpe:/a:apache:http_server`} {
		if ValidCPE(cpe) {
			t.Fatalf("非法 CPE 结构被接受: %s", cpe)
		}
	}
	for reference, valid := range map[string]bool{
		"https://httpd.apache.org/": true, "http://nginx.org/en/": true, " https://www.weaver.com.cn/ ": true,
		"https://EXAMPLE.COM": false, "https://test.example.com.": false, "": false, "https://user:pass@example.org/": false,
		"ftp://ftp.example.org/": false, "javascript:alert(1)": false, "https:///path": false,
	} {
		if ValidReferenceURL(reference) != valid {
			t.Fatalf("%q 的判定应为 %v", reference, valid)
		}
	}
}
