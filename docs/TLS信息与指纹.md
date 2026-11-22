# TLS 信息与指纹

HTTPS 目标的扫描结果带有最终页面所在连接的 TLS 摘要，规则也可以把它们写进表达式。

```go
type TLSInfo struct {
    Version     string // 如 "TLS 1.2"
    CipherSuite string // 如 "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ALPN        string // 协商的应用层协议
    JA3S        string // ServerHello 的 JA3S 摘要
    JARM        string // 62 位 JARM 指纹，WithJARM(true) 时计算
}
```

`TargetResult.TLS` 与 `BaseInfo.TLS` 描述跳转链最后一页的连接，与 `Certs` 来自同一次握手；明文目标为 `nil`。

## 版本、套件、ALPN 与 JA3S

这四项取自扫描**本来就有**的那次 TLS 握手，不增加连接，也不改变 ClientHello：引擎继续使用 Go 标准库 TLS，只在握手期间旁路记录服务端发来的握手记录，解析出 ServerHello 后停止记录。

- `Version`、`CipherSuite`、`ALPN` 取自握手完成后的连接状态。引擎的 ClientHello 不携带 ALPN 扩展（与之前的版本相同），服务端不会协商 ALPN，因此 `ALPN` 通常为空；服务端对 ALPN 的响应由 JARM 探测单独记录。
- `JA3S` 按公开的 JA3S 定义计算：取 ServerHello 的 `legacy_version`、选定的套件与扩展类型（按出现顺序，不剔除任何值），以十进制拼成 `SSLVersion,Cipher,SSLExtension`，例如 `771,49199,65281-0-11-35-16`，再取 MD5 十六进制摘要。TLS 1.3 的 `legacy_version` 固定为 771；收到 HelloRetryRequest 时取其后的 ServerHello。
- 复用的 Keep-Alive 连接沿用握手时的摘要。

TCP/UDP 规则里经 `tls://`、`ssl://`、`https://` 或 443 端口建立的 TLS 连接，以及 Raw HTTP 的 HTTPS 请求，同样记录这些字段。

## JARM

`sdk.WithJARM(true)` 为最终页面是 HTTPS 的目标计算 JARM，默认关闭。JARM 按 salesforce/jarm 公开的算法实现：向最终页面所在的主机端口依次发送 10 个参数不同的 ClientHello（TLS 版本、套件列表及顺序、GREASE、ALPN 与 supported_versions 各不相同），记录每次 ServerHello 选定的套件、版本、ALPN 与扩展列表，前 30 位编码套件与版本，后 32 位是 ALPN 与扩展列表的 SHA256 前缀。

- 每个探测是一次独立连接，SNI 使用页面的主机名，经过网络策略（`CheckTarget` 的 `Kind` 为 `tls`、`Dial`、代理）与限速；配置了代理时同样可用。
- 目标没有以 TLS 响应、或任一探测连接与读取超时时，结果为 62 个 `0`，与参考实现一致；被网络策略拒绝时不计算，`JARM` 为空。
- JARM 在构造入口页响应之前计算，入口页与之后的规则请求都携带该值。
- 探测报文、响应解析（包括对畸形响应的处理）与指纹折算逐项与参考实现一致：`pkg/network/jarm_test.go` 的测试向量由参考实现在固定随机字段下生成，10 个探测报文逐字节比对。

## 表达式变量

| 变量 | 类型 | 说明 |
|---|---|---|
| `response.tls_version` | string | 响应所在连接的 TLS 版本，如 `"TLS 1.3"`；明文响应为空串 |
| `response.cipher_suite` | string | 套件名称；明文响应为空串 |
| `response.ja3s` | string | JA3S 摘要；明文响应为空串 |
| `response.jarm` | string | 目标的 JARM 指纹；未启用 JARM 或明文目标为空串 |

```yaml
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.ja3s == "47decf033ac4c8fc9b952ff41e549679" && response.tls_version == "TLS 1.2"
expression: r0()
```

IDE 的表达式校验与补全同样认识这四个变量。
