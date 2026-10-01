// 此程序在独立模块内验证已发布的 SDK，不依赖本地 replace 或指纹目录。
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

func main() {
	if expected := os.Getenv("RELEASE_VERSION"); expected != "" && sdk.Version != expected {
		panic(fmt.Sprintf("SDK 源版本与发布标签不一致：got=%s want=%s", sdk.Version, expected))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "Apache/2.4.41")
		fmt.Fprint(w, `<html><head><title>SDK release check</title><meta name="generator" content="WordPress 6.7"></head><body>wp-content</body></html>`)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine, err := sdk.NewEngine(ctx, sdk.WithTimeout(3*time.Second))
	if err != nil {
		panic(err)
	}
	defer engine.Close()
	result, err := engine.Scan(ctx, server.URL)
	if err != nil {
		panic(err)
	}
	if result.StatusCode != http.StatusOK || result.Title != "SDK release check" || len(result.Matches) == 0 {
		panic(fmt.Sprintf("SDK 扫描结果不符合预期：status=%d title=%q matches=%d", result.StatusCode, result.Title, len(result.Matches)))
	}
	wordpress := false
	for _, match := range result.Matches {
		if match.Info.ID != "web-wordpress" {
			continue
		}
		wordpress = true
		if match.ProductVersion != "6.7" || match.Info.Source.Version != sdk.Version || len(match.Info.Source.SHA256) != 64 || match.Info.Product == nil || match.Info.Product.ID != "wordpress.wordpress" || match.Info.Vendor != "WordPress" || len(match.Info.Tags) == 0 || match.Info.Verified == nil || match.Info.Confidence != nil || match.Info.Validation.Status != "sample-tested" || len(match.MatchedRules) == 0 {
			panic(fmt.Sprintf("SDK 产品信息或版本不符合预期：%+v", match))
		}
		evidence := false
		for _, rule := range match.MatchedRules {
			for _, item := range rule.Evidence {
				evidence = evidence || item.Field == "response.body" && item.Start >= 0 && item.End > item.Start && item.Snippet != ""
			}
		}
		if !evidence {
			panic("SDK 没有返回可定位的命中证据")
		}
	}
	if !wordpress || len(result.Products) == 0 {
		panic("SDK 缺少 WordPress 命中或产品归并结果")
	}
	catalog, err := engine.RuleCatalog(ctx)
	if err != nil || len(catalog) != engine.FingerCount() || len(catalog) < 2349 {
		panic(fmt.Sprintf("SDK 规则目录不完整：count=%d error=%v", len(catalog), err))
	}
	fmt.Printf("SDK 外部模块验证通过：version=%s rules=%d status=%d matches=%d products=%d\n", sdk.Version, len(catalog), result.StatusCode, len(result.Matches), len(result.Products))
}
