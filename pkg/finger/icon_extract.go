package finger

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberspacesec/gxx/pkg/network"
)

const maxIconCandidates = 64
const maxIconAttempts = 8

type iconCandidate struct {
	path     string
	priority int
}

// GetIconURL 返回优先级最高的图标地址；同级候选保持文档顺序。
func GetIconURL(pageURL, body string) string {
	urls := extractIconURLs(pageURL, body)
	if len(urls) > 0 {
		return urls[0]
	}
	return defaultFaviconURL(pageURL)
}

// GetIconURLFromBody 直接读取只读正文，避免整页字符串副本。
func GetIconURLFromBody(pageURL string, body []byte) string {
	urls := extractIconURLs(pageURL, body)
	if len(urls) > 0 {
		return urls[0]
	}
	return defaultFaviconURL(pageURL)
}

func defaultFaviconURL(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil || u.Host == "" || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return ""
	}
	u.Path = "/favicon.ico"
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

func extractIconURLs[S metadataSource](pageURL string, body S) []string {
	urls, _ := collectIconURLs(pageURL, body)
	return urls
}

func collectIconURLs[S metadataSource](pageURL string, body S) ([]string, int) {
	page, err := url.Parse(pageURL)
	if err != nil || page.Host == "" {
		return nil, 0
	}
	base := page
	baseSeen := false
	var candidates [maxIconCandidates]iconCandidate
	n := 0
	add := func(raw string, priority int) {
		if raw == "" {
			return
		}
		if isICOPath(raw) {
			priority *= 2
		} else {
			priority = priority*2 + 1
		}
		for i := 0; i < n; i++ {
			if candidates[i].path == raw {
				if priority < candidates[i].priority {
					for i > 0 && candidates[i-1].priority > priority {
						candidates[i] = candidates[i-1]
						i--
					}
					candidates[i] = iconCandidate{raw, priority}
				}
				return
			}
		}
		at := n
		if n == len(candidates) {
			at = n - 1
			if priority >= candidates[at].priority {
				return
			}
		} else {
			n++
		}
		for at > 0 && candidates[at-1].priority > priority {
			candidates[at] = candidates[at-1]
			at--
		}
		candidates[at] = iconCandidate{raw, priority}
	}
	lexer := metadataLexer[S]{body: body}
	templateDepth := 0
	for {
		tok, ok := lexer.next()
		if !ok {
			break
		}
		if metadataEqualFold(tok.name, "template") {
			if tok.end {
				if templateDepth > 0 {
					templateDepth--
				}
			} else {
				templateDepth++
			}
			continue
		}
		if tok.end || templateDepth > 0 || len(tok.name) == 0 {
			continue
		}
		switch {
		case metadataEqualFold(tok.name, "base"):
			if !baseSeen {
				href := metadataAttribute(tok.attrs, "href")
				if href != "" {
					baseSeen = true
					if u, err := url.Parse(strings.TrimSpace(href)); err == nil {
						resolved := page.ResolveReference(u)
						if resolved.Scheme == "http" || resolved.Scheme == "https" {
							base = resolved
						}
					}
				}
			}
		case metadataEqualFold(tok.name, "link"):
			rel := metadataAttribute(tok.attrs, "rel")
			priority := -1
			for _, value := range strings.Fields(rel) {
				switch strings.ToLower(value) {
				case "icon":
					priority = 0
				case "apple-touch-icon", "apple-touch-icon-precomposed", "fluid-icon", "mask-icon", "apple-touch-startup-image", "apple-touch-icon-image", "shortcut":
					if priority < 0 {
						priority = 1
					}
				}
			}
			if priority < 0 {
				typ := metadataAttribute(tok.attrs, "type")
				if strings.EqualFold(metadataAttribute(tok.attrs, "id"), "favicon") || rel == "" && (strings.EqualFold(typ, "image/x-icon") || strings.EqualFold(typ, "image/vnd.microsoft.icon")) {
					priority = 0
				}
			}
			href := metadataAttribute(tok.attrs, "href")
			if priority >= 0 {
				add(href, priority)
			} else if isImagePath(href) {
				add(href, 4)
			}
		case metadataEqualFold(tok.name, "meta"):
			name := strings.ToLower(metadataAttribute(tok.attrs, "name"))
			if name == "msapplication-tileimage" || name == "msapplication-square70x70logo" || name == "msapplication-square150x150logo" || name == "msapplication-wide310x150logo" || name == "msapplication-square310x310logo" {
				add(metadataAttribute(tok.attrs, "content"), 1)
			} else if strings.EqualFold(metadataAttribute(tok.attrs, "property"), "og:image") || strings.EqualFold(metadataAttribute(tok.attrs, "itemprop"), "image") {
				add(metadataAttribute(tok.attrs, "content"), 2)
			}
		case metadataEqualFold(tok.name, "img"):
			src := metadataAttribute(tok.attrs, "src")
			lower := strings.ToLower(src)
			if strings.Contains(lower, "favicon") || strings.Contains(lower, "icon") {
				add(src, 3)
			}
		case metadataEqualFold(tok.name, "a"):
			href := metadataAttribute(tok.attrs, "href")
			if isImagePath(href) {
				add(href, 4)
			}
		}
	}
	var result []string
	declared := 0
	for _, candidate := range candidates[:n] {
		raw := resolveIconURL(base, candidate.path)
		if raw == "" {
			continue
		}
		duplicate := false
		for _, old := range result {
			if old == raw {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, raw)
			if candidate.priority <= 3 {
				declared++
			}
		}
	}
	return result, declared
}

func resolveIconURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 5 && strings.EqualFold(raw[:5], "data:") {
		return raw
	}
	raw = iconURLControlStripper.Replace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u = base.ResolveReference(u)
	if u.Host == "" || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return ""
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = iconQueryEscaper.Replace(u.RawQuery)
	return u.String()
}

var iconQueryEscaper = strings.NewReplacer(" ", "%20", "\"", "%22", "'", "%27", "<", "%3C", ">", "%3E")
var iconURLControlStripper = strings.NewReplacer("\t", "", "\r", "", "\n", "")

func isICOPath(raw string) bool {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	return len(raw) >= 4 && strings.EqualFold(raw[len(raw)-4:], ".ico")
}

func isImagePath(raw string) bool {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	for _, ext := range [...]string{".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"} {
		if len(raw) >= len(ext) && strings.EqualFold(raw[len(raw)-len(ext):], ext) {
			return true
		}
	}
	return false
}

// GetPageIconHash 依次验证页面候选，最后回退根路径。所有请求共享一个
// 时间预算；失败不写长期缓存，签名参数不同的地址保持独立。
func GetPageIconHash(ctx context.Context, client *network.HTTPClient, pageURL string, body []byte, options network.OptionsRequest) string {
	proxy, timeout := options.Proxy, options.Timeout
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	urls, declared := collectIconURLs(pageURL, body)
	attempted := min(declared, maxIconAttempts)
	for _, raw := range urls[:attempted] {
		if iconContextExpired(ctx) {
			return "0"
		}
		if hash := getIconHashExactCached(ctx, client, raw, proxy, timeout, pageIconHeaders(pageURL, raw, options.CustomHeaders)); hash != "" && hash != "0" {
			return hash
		}
	}
	if iconContextExpired(ctx) {
		return "0"
	}
	if raw := defaultFaviconURL(pageURL); raw != "" {
		headers := pageIconHeaders(pageURL, raw, options.CustomHeaders)
		hash := getIconHashExactCached(ctx, client, raw, proxy, timeout, headers)
		if hash != "" && hash != "0" {
			return hash
		}
		// 无声明图标时仍给默认地址第二次机会，应对短暂的 404/5xx。
		if declared == 0 && !iconContextExpired(ctx) {
			hash = getIconHashExactCached(ctx, client, raw, proxy, timeout, headers)
			if hash != "" && hash != "0" {
				return hash
			}
		}
	}
	for _, raw := range urls[declared:] {
		if attempted == maxIconAttempts || iconContextExpired(ctx) {
			break
		}
		attempted++
		if hash := getIconHashExactCached(ctx, client, raw, proxy, timeout, pageIconHeaders(pageURL, raw, options.CustomHeaders)); hash != "" && hash != "0" {
			return hash
		}
	}
	return "0"
}

func pageIconHeaders(pageURL, iconURL string, custom map[string]string) map[string]string {
	page, pageErr := url.Parse(pageURL)
	icon, iconErr := url.Parse(iconURL)
	same := pageErr == nil && iconErr == nil && strings.EqualFold(page.Scheme, icon.Scheme) && strings.EqualFold(page.Host, icon.Host)
	headers := make(map[string]string)
	if same && len(custom) > 0 {
		for key, value := range custom {
			headers[http.CanonicalHeaderKey(key)] = value
		}
	}
	if pageErr == nil && headers["Referer"] == "" && (iconErr != nil || page.Scheme != "https" || icon.Scheme == "https") {
		if same {
			page.User = nil
			page.Fragment = ""
			page.RawFragment = ""
			headers["Referer"] = page.String()
		} else {
			headers["Referer"] = page.Scheme + "://" + page.Host + "/"
		}
	}
	return headers
}
