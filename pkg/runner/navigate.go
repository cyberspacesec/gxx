package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cyberspacesec/gxx/pkg/finger"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/pkg/wappalyzer"
	"github.com/cyberspacesec/gxx/types"
	"github.com/cyberspacesec/gxx/utils/common"
)

// maxNavigationHops 是入口在资产内最多跟随的跳数（HTTP 30x 与客户端跳转合计）。
const maxNavigationHops = 5

// getBaseInfo 请求扫描入口并在资产内跟随跳转，返回链上各页与基础信息。
//
// 一个资产由协议、主机和端口确定。入口的每一跳都单独请求并保留响应：
// 30x 的 Location、Refresh、meta refresh 与跳转壳里的脚本跳转指向同一资产时继续，
// 指向其他资产时停止并记为 RedirectTo，由调用方决定是否把它当作新的目标。
// 标题、技术栈、备案与图标取自链上最后一页。
func (r *Runner) getBaseInfo(ctx context.Context, target string, timeout time.Duration) (*BaseInfoResponse, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	// 每一跳是一次独立请求，各自受 timeout 约束；整条链另设总预算。
	navCtx, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()
	hopOptions := r.buildHTTPOptions(timeout, false)
	hopOptions.Probe = true

	entry, first, err := r.requestEntry(navCtx, target, hopOptions)
	if err != nil {
		return &BaseInfoResponse{Url: target, Server: types.EmptyServerInfo()}, fmt.Errorf("发送请求失败: %w", err)
	}
	origin, err := url.Parse(entry)
	if err != nil {
		return nil, err
	}

	base := &BaseInfoResponse{Url: entry}
	visited := map[string]struct{}{navigationKey(origin): {}}
	current, resp := entry, first
	for {
		data, err := network.ReadResponseBody(resp, network.MaxDefaultBody)
		_ = resp.Body.Close()
		if err != nil {
			if len(base.pages) == 0 {
				return nil, err
			}
			break
		}
		pageURL := resp.Request.URL
		base.pages = append(base.pages, &scanPage{url: current, status: int32(resp.StatusCode), header: resp.Header, body: data, request: finger.BuildProtoRequest(resp, http.MethodGet, "", "/")})
		base.Response = resp

		next, kind := nextHop(pageURL, resp, data)
		if next == nil {
			break
		}
		hop := Redirect{Type: kind, Status: int32(resp.StatusCode), From: current, To: next.String()}
		if !network.SameOrigin(origin, next) {
			base.RedirectTo = hop.To
			base.Redirects = append(base.Redirects, hop)
			break
		}
		key := navigationKey(next)
		if _, seen := visited[key]; seen || len(base.pages) > maxNavigationHops {
			break
		}
		visited[key] = struct{}{}
		following, err := r.httpClient.SendRequestHttp(navCtx, http.MethodGet, hop.To, "", hopOptions)
		if err != nil {
			// 后续页面不可达时保留已取得的页面，仍可识别入口。
			r.log.Debug("目标 %s 跟随跳转 %s 失败: %v", entry, hop.To, err)
			break
		}
		hop.Followed = true
		base.Redirects = append(base.Redirects, hop)
		current, resp = hop.To, following
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 中间页只参与规则匹配；最后一页是识别结果所描述的页面。
	resourceOptions := r.buildHTTPOptions(timeout, true)
	last := base.pages[len(base.pages)-1]
	for _, page := range base.pages {
		page.response = finger.BuildPageResponseOwned(ctx, pageResponse(page), page.body, r.httpClient, resourceOptions, page.url, page == last)
	}
	final := pageResponse(last)
	base.FinalURL = last.url
	base.StatusCode = last.status
	base.BodyBytes = last.body
	base.Title = finger.GetTitleFromBody(navCtx, last.url, final, last.body, r.httpClient, resourceOptions)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base.Certs = finger.GetCertInfos(base.Response)
	base.Server = finger.GetServerInfoFromResponse(final)
	base.ICP = finger.ExtractICPRecordFromBody(last.body)
	if wapp, err := wappalyzer.NewWappalyzer(); err == nil {
		if data, err := wapp.GetWappalyzer(last.header, last.body); err == nil {
			base.Wappalyzer = data
		}
	}
	return base, nil
}

// requestEntry 请求入口地址。目标未带协议时先 https 后 http；两者连接同一端口且
// TCP 连接失败时不再换协议，不可达的目标只等待一次超时。
func (r *Runner) requestEntry(ctx context.Context, target string, options network.OptionsRequest) (string, *http.Response, error) {
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	candidates, samePort := network.TargetCandidates(target)
	var lastErr error
	for _, candidate := range candidates {
		if u, err := url.Parse(candidate); err != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
			return candidate, nil, fmt.Errorf("无效的目标地址 %q（只支持 http 与 https）", target)
		}
		probeCtx, connected := network.WithConnectProbe(ctx)
		resp, err := r.httpClient.SendRequestHttp(probeCtx, http.MethodGet, candidate, "", options)
		if err == nil {
			return candidate, resp, nil
		}
		lastErr = err
		if ctx.Err() != nil || samePort && !connected() {
			break
		}
	}
	return target, nil, lastErr
}

// nextHop 返回页面指向的下一跳：30x 的 Location，或页面声明的客户端跳转。
func nextHop(page *url.URL, resp *http.Response, body []byte) (*url.URL, string) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, ""
		}
		next, err := page.Parse(location)
		if err != nil || next.Host == "" || next.Scheme != "http" && next.Scheme != "https" {
			return nil, ""
		}
		next.Fragment, next.RawFragment = "", ""
		return next, finger.RedirectHTTP
	}
	return finger.ClientRedirect(page, resp.Header, body)
}

// navigationKey 用于识别跳转回环：忽略片段，空路径等同于根路径。
func navigationKey(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return network.Origin(u) + path + "?" + u.RawQuery
}

// pageResponse 还原一页的响应头信息，供标题、Server 与资源提取使用。
func pageResponse(page *scanPage) *http.Response {
	u, _ := url.Parse(page.url)
	return &http.Response{StatusCode: int(page.status), Status: fmt.Sprintf("%d %s", page.status, http.StatusText(int(page.status))), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: page.header, Body: http.NoBody, Request: &http.Request{Method: http.MethodGet, URL: u, Header: make(http.Header)}}
}

// warmUpRequestCache 把入口跳转链写入本次扫描的请求缓存，并返回链上较早的各页。
//
// 根路径 GET 规则默认匹配最后一页；较早的各页由 evaluateFingerprint 依次补评。
// 不跟随重定向的根路径规则只看第一页，直接复用入口响应，不再另发请求。
func (r *Runner) warmUpRequestCache(result *TargetResult, base *BaseInfoResponse, cache *CacheManager) []*scanPage {
	last, first := base.pages[len(base.pages)-1], base.pages[0]
	result.LastRequest, result.LastResponse = last.request, last.response
	root := common.ParseTarget(result.URL, "/")
	cache.updateOwnedTargetCache(map[string]any{"request": last.request, "response": last.response}, root, true)
	cache.updateOwnedTargetCache(map[string]any{"request": first.request, "response": first.response}, root, false)
	earlier := make([]*scanPage, 0, len(base.pages)-1)
	for i := len(base.pages) - 2; i >= 0; i-- {
		earlier = append(earlier, base.pages[i])
	}
	return earlier
}

// ResolveTarget 确定目标所属的资产地址：已带协议时原样返回，否则请求一次入口
// 以确定 https 还是 http。
func (r *Runner) ResolveTarget(ctx context.Context, target string) (string, error) {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, network.HttpPrefix) || strings.HasPrefix(target, network.HttpsPrefix) {
		return target, nil
	}
	ctx, done, err := r.life.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer done()
	options := r.buildHTTPOptions(r.requestTimeout(), false)
	options.Probe = true
	entry, resp, err := r.requestEntry(network.WithCookieJar(ctx), target, options)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	return entry, nil
}
