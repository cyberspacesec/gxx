package wappalyzer

import (
	"reflect"
	"slices"
	"testing"

	upstream "github.com/projectdiscovery/wappalyzergo"
)

// FormatData 必须把命名分类归入对应字段，其余分类归入 Other，且每个切片去重并排序。
func TestFormatDataSurfacesAllCategoriesSorted(t *testing.T) {
	w := &Wappalyzer{}
	data := map[string]upstream.AppInfo{
		"WordPress":        {Categories: []string{"CMS", "Blogs"}},
		"MySQL":            {Categories: []string{"Databases"}},
		"Shopify":          {Categories: []string{"Ecommerce"}},
		"Cloudflare":       {Categories: []string{"CDN", "Reverse proxies"}},
		"Google Analytics": {Categories: []string{"Analytics"}},
		"Ubuntu":           {Categories: []string{"Operating systems"}},
		"Nginx":            {Categories: []string{"Web servers", "Reverse proxies"}},
		"jQuery":           {Categories: []string{"JavaScript libraries"}},
		// 仅含未命名分类，必须归入 Other 而非被丢弃。
		"SomeWidget": {Categories: []string{"Widgets"}},
		"SomeChat":   {Categories: []string{"Live chat"}},
	}
	got := w.FormatData(data)

	checks := map[string][]string{
		"CMS":              {"WordPress"},
		"Databases":        {"MySQL"},
		"Ecommerce":        {"Shopify"},
		"Analytics":        {"Google Analytics"},
		"OperatingSystems": {"Ubuntu"},
		"WebServers":       {"Nginx"},
	}
	v := reflect.ValueOf(*got)
	for field, want := range checks {
		actual := v.FieldByName(field).Interface().([]string)
		if !reflect.DeepEqual(actual, want) {
			t.Errorf("%s=%v 期望 %v", field, actual, want)
		}
	}
	// Cloudflare 同时属于 CDN 与 Reverse proxies，两字段都应出现，且不进 Other。
	if !slices.Contains(got.CDN, "Cloudflare") || !slices.Contains(got.ReverseProxies, "Cloudflare") {
		t.Errorf("Cloudflare 应同时出现在 CDN 与 ReverseProxies: CDN=%v RP=%v", got.CDN, got.ReverseProxies)
	}
	// 未命名分类归入 Other。
	for _, name := range []string{"SomeWidget", "SomeChat"} {
		if !slices.Contains(got.Other, name) {
			t.Errorf("%s 未进入 Other: %v", name, got.Other)
		}
	}
	if slices.Contains(got.Other, "WordPress") {
		t.Error("命中命名分类的技术不应重复进入 Other")
	}
	// 排序稳定。
	if !slices.IsSorted(got.Other) {
		t.Errorf("Other 未排序: %v", got.Other)
	}
}

// 同一输入多次识别输出顺序必须一致。
func TestFormatDataStableOrder(t *testing.T) {
	w := &Wappalyzer{}
	data := map[string]upstream.AppInfo{
		"jQuery":        {Categories: []string{"JavaScript libraries"}},
		"Lodash":        {Categories: []string{"JavaScript libraries"}},
		"Moment.js":     {Categories: []string{"JavaScript libraries"}},
		"Underscore.js": {Categories: []string{"JavaScript libraries"}},
		"Bootstrap":     {Categories: []string{"UI frameworks"}},
	}
	first := w.FormatData(data).JavaScriptLibraries
	for i := 0; i < 20; i++ {
		if got := w.FormatData(data).JavaScriptLibraries; !reflect.DeepEqual(got, first) {
			t.Fatalf("第 %d 次输出顺序不同: %v 首次 %v", i, got, first)
		}
	}
	if !slices.IsSorted(first) {
		t.Errorf("JavaScriptLibraries 未排序: %v", first)
	}
}
