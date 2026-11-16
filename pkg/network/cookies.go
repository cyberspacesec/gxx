package network

import (
	"context"
	"net/http"
	"net/http/cookiejar"

	"golang.org/x/net/publicsuffix"
)

type cookieJarKey struct{}

// WithCookieJar 为 ctx 下的全部请求建立一个独立的 Cookie 会话。
//
// 一次扫描的入口请求、规则请求与页面资源共用同一会话，扫描结束后随 ctx 释放。
// 会话不属于 HTTPClient：不同扫描互不可见，引擎也不会随扫描目标数量累积 Cookie。
// ctx 已有会话时原样返回。
func WithCookieJar(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if cookieJarFrom(ctx) != nil {
		return ctx
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return ctx
	}
	return context.WithValue(ctx, cookieJarKey{}, http.CookieJar(jar))
}

func cookieJarFrom(ctx context.Context) http.CookieJar {
	jar, _ := ctx.Value(cookieJarKey{}).(http.CookieJar)
	return jar
}
