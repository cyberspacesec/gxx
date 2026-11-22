package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/cyberspacesec/gxx/internal/lifecycle"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/pkg/runner"
)

// NetworkPolicy 约束引擎的全部出站连接：HTTP、Raw HTTP、TCP、UDP、图标、附属资源、
// 跳转、TLS 探测与代理健康探测。各字段为 nil 时保持默认行为，字段说明见 network.Policy。
type NetworkPolicy = network.Policy

// TargetRequest 描述一次即将发往目标的连接，供 NetworkPolicy.CheckTarget 判断。
type TargetRequest = network.TargetRequest

// RequestKind 是一次出站连接的用途。
type RequestKind = network.RequestKind

// RedirectAction 是 NetworkPolicy.Redirect 对一次跳转的决定。
type RedirectAction = network.RedirectAction

// 出站连接的用途。
const (
	RequestHTTP     = network.RequestHTTP
	RequestRaw      = network.RequestRaw
	RequestTCP      = network.RequestTCP
	RequestUDP      = network.RequestUDP
	RequestIcon     = network.RequestIcon
	RequestResource = network.RequestResource
	RequestTLS      = network.RequestTLS
)

// 跳转决定。
const (
	RedirectFollow = network.RedirectFollow
	RedirectStop   = network.RedirectStop
)

// WithNetworkPolicy 设置引擎级网络策略，作用于该引擎的全部扫描与基础信息请求。
//
// Dial 替代直连拨号，配置代理时用于连接代理服务器本身；CheckTarget 在每次发往目标之前
// 调用（含重试、跳转与经代理隧道的目标），返回错误即拒绝且不会有任何字节发往该目标；
// Redirect 可以阻止跟随 30x、刷新与脚本跳转，不访问的地址记入 RedirectTo；
// WrapTransport 包装 HTTP 请求的底层 RoundTripper。
func WithNetworkPolicy(policy NetworkPolicy) Option {
	return func(c *engineConfig) error {
		c.policy = policy
		return nil
	}
}

// scanConfig 是单次扫描的附加配置。
type scanConfig struct {
	policy NetworkPolicy
}

// ScanOption 配置一次 ScanWith 或 DebugRule。
type ScanOption func(*scanConfig)

// ScanNetworkPolicy 设置本次扫描的网络策略，逐字段覆盖引擎级策略：非 nil 的字段替换
// 引擎级的同名字段，nil 字段沿用引擎级。
//
// 设置了 Dial 时，本次扫描的 HTTP 连接不进入连接池，不同扫描的拨号互不混用；
// 已缓存的 Transport 照常复用，不为每次扫描新建 Transport。
func ScanNetworkPolicy(policy NetworkPolicy) ScanOption {
	return func(c *scanConfig) { c.policy = policy }
}

// ScanWith 与 Scan 相同，并应用本次扫描的附加配置。未传任何选项时与 Scan 完全一致。
func (e *Engine) ScanWith(ctx context.Context, target string, opts ...ScanOption) (*TargetResult, error) {
	ctx, done, err := e.life.Begin(ctx)
	if err != nil {
		if errors.Is(err, lifecycle.ErrClosed) {
			err = ErrEngineClosed
		}
		return nil, err
	}
	defer done()
	if e.IsClosed() {
		return nil, ErrEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, ErrEmptyTarget
	}
	var cfg scanConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	res, err := e.runner.ScanTargetWith(ctx, target, cfg.runnerOptions())
	if err != nil {
		return nil, fmt.Errorf("scan target %q: %w", target, errors.Join(ErrScanFailed, err))
	}
	if res == nil {
		return nil, fmt.Errorf("%w: target=%s", ErrEmptyResult, target)
	}
	out := e.convertTargetResult(res)
	e.dispatchWriter(ctx, out)
	return out, nil
}

func (c *scanConfig) runnerOptions() runner.ScanOptions {
	return runner.ScanOptions{Policy: c.policy}
}
