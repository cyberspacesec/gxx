/*
  - Package main
    @Author: zhizhuo
    @IDE：GoLand
    @File: wappalyzer_test.go.go
    @Date: 2025/4/16 下午2:54*
*/
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	wappalyzers "github.com/cyberspacesec/gxx/v2/pkg/wappalyzer"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type WappalyzerType struct {
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
	Other                []string `json:"other"`                  //其他杂项
}

func FormatData(data map[string]wappalyzer.AppInfo) WappalyzerType {
	var wappalyzerData WappalyzerType
	for fin, d := range data {
		for _, c := range d.Categories {
			if c == "Web servers" {
				wappalyzerData.WebServers = append(wappalyzerData.WebServers, fin)
			}
			if c == "Web frameworks" {
				wappalyzerData.WebFrameworks = append(wappalyzerData.WebFrameworks, fin)
			}
			if c == "JavaScript frameworks" {
				wappalyzerData.JavaScriptFrameworks = append(wappalyzerData.JavaScriptFrameworks, fin)
			}
			if c == "JavaScript libraries" {
				wappalyzerData.JavaScriptLibraries = append(wappalyzerData.JavaScriptLibraries, fin)
			}
			if c == "Miscellaneous" {
				wappalyzerData.Other = append(wappalyzerData.Other, fin)
			}
			if c == "Programming languages" {
				wappalyzerData.ProgrammingLanguages = append(wappalyzerData.ProgrammingLanguages, fin)
			}
			if c == "Security" {
				wappalyzerData.Security = append(wappalyzerData.Security, fin)
			}
			if c == "Hosting panels" {
				wappalyzerData.HostingPanels = append(wappalyzerData.HostingPanels, fin)
			}
			if c == "Caching" {
				wappalyzerData.Caching = append(wappalyzerData.Caching, fin)
			}
			if c == "Reverse proxies" {
				wappalyzerData.ReverseProxies = append(wappalyzerData.ReverseProxies, fin)
			}
		}
	}
	return wappalyzerData
}

func TestGetWappalyserInfo(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 wappalyzer 测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wapp, err := wappalyzers.NewWappalyzer()
	if err != nil {
		log.Fatal(fmt.Sprintf("wappalyzer初始化错误，错误信息：%s", err.Error()))
	}
	res, err := wapp.GetWappalyzer(resp.Header, data)
	if err != nil {
		log.Fatal(fmt.Sprintf("获取站点使用技术信息出错，错误信息：%s", err.Error()))
	}
	fmt.Println(res)
	fmt.Println(strings.Repeat("=", 50))

	jsonData, err := json.MarshalIndent(res, "", " ")
	fmt.Println(string(jsonData))
	fmt.Println(strings.Repeat("=", 50))

	fmt.Println(fmt.Sprintf("测试站点：%s", url))
	fmt.Println(fmt.Sprintf("开发语言：%s", res.ProgrammingLanguages))
	fmt.Println(fmt.Sprintf("WEB服务器：%s", res.WebServers))
	fmt.Println(fmt.Sprintf("代理服务器：%s", res.ReverseProxies))
	fmt.Println(fmt.Sprintf("JavaScript框架：%s", res.JavaScriptFrameworks))
	fmt.Println(fmt.Sprintf("JavaScript库：%s", res.JavaScriptLibraries))
	fmt.Println(fmt.Sprintf("WEB框架：%s", res.WebFrameworks))
	fmt.Println(fmt.Sprintf("静态站点生成器：%s", res.StaticSiteGenerator))
	fmt.Println(fmt.Sprintf("站点缓存：%s", res.Caching))
	fmt.Println(fmt.Sprintf("站点安全：%s", res.Security))
	fmt.Println(fmt.Sprintf("主机面板：%s", res.HostingPanels))
	fmt.Println(fmt.Sprintf("其他杂项：%s", res.Other))

}
func TestWappalyzerGet(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 wappalyzer 测试；设置 GXX_INTEGRATION=1 启用")
	}
	url := "https://www.baidu.com/"
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // Ignoring error for example
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal(err)
	}
	//fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
	//fmt.Println(fingerprints)
	//printFingerprintsAsJSON(fingerprints)

	fingerprintsWithCats := wappalyzerClient.FingerprintWithInfo(resp.Header, data)
	jsonDataS, err := json.MarshalIndent(fingerprintsWithCats, "", " ")
	fmt.Println(string(jsonDataS))
	fmt.Println(strings.Repeat("=", 50))
	a := FormatData(fingerprintsWithCats)

	jsonData, err := json.MarshalIndent(a, "", " ")
	fmt.Println(string(jsonData))
	fmt.Println(strings.Repeat("=", 50))

	fmt.Println(fmt.Sprintf("测试站点：%s", url))
	fmt.Println(fmt.Sprintf("开发语言：%s", a.ProgrammingLanguages))
	fmt.Println(fmt.Sprintf("WEB服务器：%s", a.WebServers))
	fmt.Println(fmt.Sprintf("代理服务器：%s", a.ReverseProxies))
	fmt.Println(fmt.Sprintf("JavaScript框架：%s", a.JavaScriptFrameworks))
	fmt.Println(fmt.Sprintf("JavaScript库：%s", a.JavaScriptLibraries))
	fmt.Println(fmt.Sprintf("WEB框架：%s", a.WebFrameworks))
	fmt.Println(fmt.Sprintf("静态站点生成器：%s", a.StaticSiteGenerator))
	fmt.Println(fmt.Sprintf("站点缓存：%s", a.Caching))
	fmt.Println(fmt.Sprintf("站点安全：%s", a.Security))
	fmt.Println(fmt.Sprintf("主机面板：%s", a.HostingPanels))
	fmt.Println(fmt.Sprintf("其他杂项：%s", a.Other))
}
