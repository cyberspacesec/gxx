/*
  - Package request
    @Author: zhizhuo
    @IDE：GoLand
    @File: raw_http.go
    @Date: 2025/2/8 下午4:05*
*/
package network

import (
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/utils/common"
	"github.com/cyberspacesec/gxx/utils/proto"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// SendRawRequest 发送当前实例的原始 HTTP 报文，遵循其取消、代理、TLS 和超时配置。
func SendRawRequest(ctx context.Context, client *HTTPClient, request, baseurl string, variableMap map[string]any, options OptionsRequest) error {
	var err error
	var resp *http.Response

	variableMap["request"] = nil
	variableMap["response"] = nil

	request = AssignVariableRaw(request, variableMap)

	rhttp, err := Parse(request, baseurl, true)
	if err != nil {
		return fmt.Errorf("解析 Raw HTTP 请求失败: %w", err)
	}

	resp, err = client.SendRawRequest(ctx, request, baseurl, options)
	if err != nil {
		return fmt.Errorf("发送 Raw HTTP 请求失败: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// 限制读取大小，避免异常大响应体
	respBody, err := ReadResponseBody(resp, MaxDefaultBody)
	if err != nil {
		return fmt.Errorf("读取 Raw HTTP 响应失败: %w", err)
	}

	dumpedResponseHeaders, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return fmt.Errorf("编码 Raw HTTP 响应失败: %w", err)
	}

	tempResultResponse := &proto.Response{}
	tempResultResponse.Status = int32(resp.StatusCode)
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultResponse.Url = common.Url2UrlType(requrl)
	}
	newheader2 := make(map[string]string)
	respHeaderSlice := strings.Split(strings.TrimSpace(string(dumpedResponseHeaders)), "\n")
	for _, h := range respHeaderSlice {
		h = strings.Trim(h, "\r\n")
		hslice := strings.SplitN(h, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader2[k] != "" {
			newheader2[k] += v
		} else {
			newheader2[k] = v
		}
	}
	tempResultResponse.Headers = newheader2
	tempResultResponse.ContentType = resp.Header.Get("Content-Type")
	tempResultResponse.Body = respBody
	tempResultResponse.Raw = []byte(string(dumpedResponseHeaders) + "\n" + string(respBody))
	tempResultResponse.RawHeader = dumpedResponseHeaders
	variableMap["response"] = tempResultResponse

	tempResultRequest := &proto.Request{}
	tempResultRequest.Method = rhttp.Method
	if requrl, err := url.Parse(baseurl); err == nil {
		tempResultRequest.Url = common.Url2UrlType(requrl)
	}
	newheader1 := map[string]string{}
	for _, v := range rhttp.UnsafeHeaders {
		key, _ := v.Key, v.Value
		if len(strings.TrimSpace(key)) == 0 {
			continue
		}
		key = strings.Trim(key, ":")
		hslice := strings.SplitN(key, ":", 2)
		if len(hslice) != 2 {
			continue
		}
		k := strings.ToLower(hslice[0])
		v := strings.TrimLeft(hslice[1], " ")
		if newheader1[k] != "" {
			newheader1[k] += v
		} else {
			newheader1[k] = v
		}
	}
	tempResultRequest.Headers = newheader1
	tempResultRequest.Raw = rhttp.UnsafeRawBytes
	if len(string(rhttp.UnsafeRawBytes)) > 0 {
		rawSplit := strings.Split(string(rhttp.UnsafeRawBytes), "\n\n")
		if len(rawSplit) > 1 {
			tempResultRequest.RawHeader = []byte(rawSplit[0])
		} else {
			tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
		}
	} else {
		tempResultRequest.RawHeader = rhttp.UnsafeRawBytes
	}
	tempResultRequest.Body = []byte(rhttp.Data)
	tempResultRequest.ContentType = tempResultRequest.Headers["content-type"]
	variableMap["request"] = tempResultRequest

	variableMap["fulltarget"] = fmt.Sprintf("%s://%s%s", tempResultRequest.Url.Scheme, tempResultRequest.Url.Host, tempResultRequest.Url.Path)

	return err
}

func AssignVariableRaw(find string, variableMap map[string]any) string {
	for k, v := range variableMap {
		oldstr := "{{" + k + "}}"
		if !strings.Contains(find, oldstr) {
			continue
		}
		find = strings.ReplaceAll(find, oldstr, fmt.Sprintf("%v", v))
	}
	return find
}
