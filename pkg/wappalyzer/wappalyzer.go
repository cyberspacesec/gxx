/*
  - Package wappalyzer
    @Author: zhizhuo
    @IDE：GoLand
    @File: wappalyzer.go
    @Date: 2025/4/17 下午1:59*
*/
package wappalyzer

import (
	"fmt"
	"slices"
	"sort"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	globalWapp     *Wappalyzer
	globalWappOnce sync.Once
	globalWappErr  error
)

// Wappalyzer 技术识别器结构体
type Wappalyzer struct {
	client *httpMatcher
}

// TypeWappalyzer 存储网站技术栈信息的结构体。
// 命名字段覆盖高价值分类；其余未命名分类统一归入 Other，确保不丢弃任何识别结果。
type TypeWappalyzer struct {
	WebServers           []string `json:"web_servers"`            //WEB服务器
	ReverseProxies       []string `json:"reverse_proxies"`        //代理服务器
	JavaScriptFrameworks []string `json:"java_script_frameworks"` //JS框架
	JavaScriptLibraries  []string `json:"java_script_libraries"`  //JavaScript库
	WebFrameworks        []string `json:"web_frameworks"`         //WEB框架
	StaticSiteGenerator  []string `json:"static_site_generator"`  //静态站点生成器
	ProgrammingLanguages []string `json:"programming_languages"`  //开发语言
	Caching              []string `json:"caching"`                //站点缓存
	Security             []string `json:"security"`               //站点安全
	HostingPanels        []string `json:"hosting_panels"`         //主机面板
	CMS                  []string `json:"cms"`                    //内容管理系统
	Databases            []string `json:"databases"`              //数据库
	Ecommerce            []string `json:"ecommerce"`              //电商平台
	CDN                  []string `json:"cdn"`                    //内容分发网络
	Analytics            []string `json:"analytics"`              //统计分析
	OperatingSystems     []string `json:"operating_systems"`      //操作系统
	Other                []string `json:"other"`                  //其他未归类组件
}

// NewWappalyzer 返回全局共享的 Wappalyzer 单例
// Wappalyzer 内部只做只读匹配，线程安全，无需每次创建新实例
func NewWappalyzer() (*Wappalyzer, error) {
	globalWappOnce.Do(func() {
		client, err := newHTTPMatcher(wappalyzer.GetRawFingerprints())
		if err != nil {
			globalWappErr = fmt.Errorf("初始化Wappalyzer失败: %w", err)
			return
		}
		globalWapp = &Wappalyzer{client: client}
	})
	if globalWappErr != nil {
		return nil, globalWappErr
	}
	return globalWapp, nil
}

// FormatData 将 wappalyzer 原始数据格式化为自定义结构。
//
// 命名分类映射到对应字段；任何不在命名表中的分类，其技术会归入 Other，
// 避免像旧实现那样整体丢弃（上游约 87% 的应用分类此前被静默丢弃）。
// 每个切片在返回前去重并排序，保证同一输入的输出稳定可复现。
func (w *Wappalyzer) FormatData(data map[string]wappalyzer.AppInfo) *TypeWappalyzer {
	var result TypeWappalyzer

	categoryMap := map[string]*[]string{
		"Web servers":           &result.WebServers,
		"Web frameworks":        &result.WebFrameworks,
		"JavaScript frameworks": &result.JavaScriptFrameworks,
		"JavaScript libraries":  &result.JavaScriptLibraries,
		"Miscellaneous":         &result.Other,
		"Programming languages": &result.ProgrammingLanguages,
		"Security":              &result.Security,
		"Hosting panels":        &result.HostingPanels,
		"Caching":               &result.Caching,
		"Reverse proxies":       &result.ReverseProxies,
		"Static site generator": &result.StaticSiteGenerator,
		"CMS":                   &result.CMS,
		"Databases":             &result.Databases,
		"Ecommerce":             &result.Ecommerce,
		"CDN":                   &result.CDN,
		"Analytics":             &result.Analytics,
		"Operating systems":     &result.OperatingSystems,
	}

	for techName, info := range data {
		placed := false
		for _, category := range info.Categories {
			if slice, exists := categoryMap[category]; exists {
				*slice = append(*slice, techName)
				placed = true
			}
		}
		// 所有分类都未命中命名表时归入 Other，确保结果不丢失。
		if !placed {
			result.Other = append(result.Other, techName)
		}
	}

	for _, slice := range categoryMap {
		dedupeSort(slice)
	}
	dedupeSort(&result.Other)
	return &result
}

// dedupeSort 对切片原地去重并排序，使输出稳定。
func dedupeSort(slice *[]string) {
	if len(*slice) == 0 {
		return
	}
	sort.Strings(*slice)
	*slice = slices.Compact(*slice)
}

// GetWappalyzer 分析HTTP响应头和响应体，识别网站使用的技术栈
func (w *Wappalyzer) GetWappalyzer(respHeader map[string][]string, respData []byte) (*TypeWappalyzer, error) {
	if w == nil || w.client == nil {
		return nil, fmt.Errorf("wappalyzer实例未正确初始化")
	}
	fingerprintsWithCats := w.client.FingerprintWithInfo(respHeader, respData)
	return w.FormatData(fingerprintsWithCats), nil
}
