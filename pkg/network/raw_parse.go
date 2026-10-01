/*
  - Package request
    @Author: zhizhuo
    @IDE：GoLand
    @File: raw_parse.go
    @Date: 2025/2/20 上午10:32*
*/
package network

import (
	"github.com/cyberspacesec/gxx/utils/proto"
)

func RawParse(nc *Client, data []byte, res []byte, variableMap map[string]any) error {
	variableMap["request"] = &proto.Request{
		Raw: []byte(nc.address + "\r\n" + string(data)),
	}
	variableMap["response"] = &proto.Response{
		Raw: res,
	}
	variableMap["fulltarget"] = nc.address
	return nil
}
