// 此程序在独立模块内验证已发布的 SDK，不依赖本地 replace 或指纹目录。
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/cyberspacesec/gxx/sdk"
)

func main() {
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
	fmt.Printf("SDK 外部模块验证通过：status=%d matches=%d\n", result.StatusCode, len(result.Matches))
}
