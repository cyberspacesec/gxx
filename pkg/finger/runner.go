/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: runner.go
    @Date: 2025/2/20 下午3:37*
*/
package finger

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/logger"
	"io"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 5 * time.Second

// SendRequest 使用指定 HTTP 客户端发送 yaml poc 请求。
// parentCtx 取消或超时后，请求会尽快结束（与 Scan(ctx) 语义一致）。
func SendRequest(parentCtx context.Context, client *network.HTTPClient, target string, req RuleRequest, rule Rule, variableMap map[string]any, options network.OptionsRequest) (map[string]any, error) {
	if client == nil {
		client = network.DefaultHTTPClient()
	}

	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}
	options.FollowRedirects = rule.Request.ShouldFollowRedirects()
	if len(rule.Request.Headers) > 0 {
		headers := make(map[string]string, len(options.CustomHeaders)+len(rule.Request.Headers))
		for k, v := range options.CustomHeaders {
			headers[k] = v
		}
		options.CustomHeaders = headers
	}

	if parentCtx == nil {
		parentCtx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(parentCtx, options.Timeout)
	defer cancel()
	if err := reqCtx.Err(); err != nil {
		return variableMap, err
	}

	// 处理path
	newPath := formatPath(rule.Request.Path)

	// 处理url
	urlStr := common.ParseTarget(target, newPath)

	// 处理body
	rule.Request.Body = formatBody(rule.Request.Body, rule.Request.Headers["Content-Type"], variableMap)

	// 处理自定义headers
	for k, v := range rule.Request.Headers {
		options.CustomHeaders[k] = v
	}

	// 判断请求方式
	reqType := strings.ToLower(strings.TrimSpace(rule.Request.Type))
	if len(reqType) > 0 && reqType != common.HttpType {
		if err := client.WaitRequest(reqCtx, target); err != nil {
			return nil, err
		}
		switch reqType {
		case common.TcpType, common.UdpType:
			host := SetVariableMap(rule.Request.Host, variableMap)
			if host == "" {
				host = target
			}
			// 主机、端口、是否握手与 ServerName 全部由 network.ParseEndpoint 一处决定。
			nc, err := network.NewClientContext(reqCtx, host, network.TcpOrUdpConfig{
				Network:     reqType,
				ReadTimeout: time.Duration(rule.Request.ReadTimeout) * time.Second,
				ReadIdle:    time.Duration(rule.Request.ReadIdle) * time.Millisecond,
				DialTimeout: options.Timeout,
				ReadSize:    rule.Request.ReadSize,
				MaxRetries:  1,
				ProxyURL:    options.Proxy,
				VerifyTLS:   !options.InsecureSkipVerify,
			})
			if err != nil {
				return nil, err
			}
			defer nc.Close()
			data := SetVariableMap(rule.Request.Data, variableMap)
			if strings.EqualFold(rule.Request.DataType, "hex") {
				data = common.FromHex(data)
			}
			if err := nc.Send([]byte(data)); err != nil {
				return nil, err
			}
			res, err := nc.Receive()
			if err != nil {
				return nil, err
			}
			if err = network.RawParse(nc, []byte(data), res, variableMap); err != nil {
				return nil, err
			}
			return variableMap, nil
		default:
			// YAML 加载时已拒绝未实现的类型；不经 YAML 构造的规则在这里报错，
			// 不能落到 HTTP 路径当作明文请求执行。
			return nil, fmt.Errorf("unsupported rule type %q (supported: http, tcp, udp)", reqType)
		}
	} else {
		if len(rule.Request.Raw) > 0 {
			logger.FromContext(reqCtx).Debug("执行 raw 格式请求")
			err := network.SendRawRequest(reqCtx, client, rule.Request.Raw, target, variableMap, options)
			if err != nil {
				return variableMap, err
			}
			return variableMap, nil
		}
	}

	// 处理协议，增加通信协议
	NewUrlStr, err := client.CheckProtocol(reqCtx, urlStr, options.Proxy, options.Timeout)
	if err != nil {
		logger.FromContext(reqCtx).Debug("检查http通信协议出错，错误信息：%s", err)
		if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
			NewUrlStr = "http://" + target
		}
	}

	logger.FromContext(reqCtx).Debug("请求URL：%s", NewUrlStr)

	// 发送请求
	start := time.Now()
	resp, err := client.SendRequestHttp(reqCtx, req.Method, NewUrlStr, rule.Request.Body, options)
	if err != nil {
		logger.FromContext(reqCtx).Debug("发送请求出错，错误信息：%s", err)
		return variableMap, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	// 请求已按 NewUrlStr 发出，解析通常不会失败；失败时保留响应自带的 URL，避免置空后在构造请求时解引用 nil。
	if newURL, parseErr := url.Parse(NewUrlStr); parseErr == nil {
		resp.Request.URL = newURL
	}
	// 处理请求的raw
	protoReq := buildProtoRequest(resp, rule.Request)
	variableMap["request"] = protoReq

	// 读取响应体
	body, err := network.ReadResponseBody(resp, network.MaxDefaultBody)
	if err != nil {
		logger.FromContext(reqCtx).Debug("读取响应体出错：%s", err)
		// 即使读取响应体出错，也继续处理，使用空响应体
		return variableMap, err
	}
	milliseconds := time.Since(start).Milliseconds()
	// 处理响应的raw，传入代理参数
	protoResp := BuildProtoResponseOwned(parentCtx, resp, body, milliseconds, client, options)
	variableMap["response"] = protoResp
	return variableMap, nil
}
