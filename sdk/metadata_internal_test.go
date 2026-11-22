package sdk

import (
	"testing"
)

func TestProductReferencesValidation(t *testing.T) {
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
