package sdk

import (
	"testing"
)

func TestProductCPEAndReferencesValidation(t *testing.T) {
	for _, cpe := range []string{`cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*`} {
		if !validCPE(cpe) {
			t.Fatalf("合法 CPE 结构被拒绝: %s", cpe)
		}
	}
	for _, cpe := range []string{`cpe:2.3:a:vendor:product:*`, `cpe:2.3:x:vendor:product:*:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:`, `cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:\`} {
		if validCPE(cpe) {
			t.Fatalf("非法 CPE 结构被接受: %s", cpe)
		}
	}
	if len(validReferences([]string{"https://EXAMPLE.COM", "https://test.example.com.", "", "https://user:pass@example.org/", "https://httpd.apache.org/", "https://httpd.apache.org/"})) != 1 {
		t.Fatal("无效引用或占位链接进入结果")
	}
}

func TestCanonicalCatalogOverrideIsConsistentAcrossAliases(t *testing.T) {
	index, err := productIndex([]ProductDefinition{{ProductInfo: ProductInfo{ID: "apache.http-server", Name: "目录名称", Vendor: "目录厂商"}, RuleIDs: []string{"web-apache-http"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"web-apache-http", "apache-detect", "web-apache2-ubuntu默认页面"} {
		if product := index[id]; product.Name != "目录名称" || product.Vendor != "目录厂商" {
			t.Fatalf("同一产品的不同来源使用了不同目录: %s %+v", id, product)
		}
	}
}
