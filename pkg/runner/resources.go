package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"

	"github.com/cyberspacesec/gxx/pkg/network"
)

// 附属资源的类型。
const (
	ResourceRobots  = "robots"
	ResourceSitemap = "sitemap"
)

// DefaultResourceBytes 是每个附属资源默认保留的正文字节数。
const DefaultResourceBytes = 64 << 10

// ResourceOptions 选择要读取的附属资源。MaxBytes 是每个资源保留的正文上限，0 取默认值。
type ResourceOptions struct {
	Robots   bool
	Sitemap  bool
	MaxBytes int
}

// Resource 是一个附属资源。Body 是正文的前 MaxBytes 字节；BodyBytes 与 SHA256 覆盖实际
// 读取的正文（受引擎正文读取上限约束）；Truncated 表示 Body 短于实际正文或正文超过读取上限。
type Resource struct {
	Kind       string
	URL        string
	StatusCode int
	Body       []byte
	BodyBytes  int64
	SHA256     string
	Truncated  bool
}

// fetchResources 读取最终页面所在资产的附属资源，请求失败的资源不出现在结果中。
func (r *Runner) fetchResources(ctx context.Context, page string, options network.OptionsRequest) []Resource {
	cfg := r.cfg.Resources
	if !cfg.Robots && !cfg.Sitemap {
		return nil
	}
	base, err := url.Parse(page)
	if err != nil || network.Origin(base) == "" {
		return nil
	}
	limit := cfg.MaxBytes
	if limit <= 0 {
		limit = DefaultResourceBytes
	}
	var resources []Resource
	for _, item := range []struct {
		enabled bool
		kind    string
		path    string
	}{{cfg.Robots, ResourceRobots, "/robots.txt"}, {cfg.Sitemap, ResourceSitemap, "/sitemap.xml"}} {
		if !item.enabled || ctx.Err() != nil {
			continue
		}
		target := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: item.path}
		resp, err := r.httpClient.GetSiteResource(ctx, target.String(), options)
		if err != nil {
			r.log.Debug("读取 %s 失败: %v", target, err)
			continue
		}
		data, truncated, err := network.ReadResponseBodyLimit(resp, options.ReadLimit())
		_ = resp.Body.Close()
		if err != nil {
			r.log.Debug("读取 %s 正文失败: %v", target, err)
			continue
		}
		sum := sha256.Sum256(data)
		kept := data
		if len(kept) > limit {
			kept = append([]byte(nil), data[:limit]...)
		}
		resources = append(resources, Resource{Kind: item.kind, URL: resp.Request.URL.String(), StatusCode: resp.StatusCode, Body: kept, BodyBytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Truncated: truncated || len(data) > limit})
	}
	return resources
}
