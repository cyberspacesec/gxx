/** GXX 指纹编写常用提示与预设 */

export interface PresetItem {
  key: string
  value: string
  desc: string
}

export const SET_VAR_PRESETS: PresetItem[] = [
  { key: 'num', value: 'randomInt(800000000, 1000000000)', desc: '随机整数' },
  { key: 'payload', value: 'randomLowercase(20)', desc: '随机小写串' },
  { key: 'hostname', value: 'request.url.host', desc: '目标主机' },
  { key: 'host', value: 'request.url.domain', desc: '根域名' },
  { key: 'path', value: '"/admin/login"', desc: '固定路径（payloads 常用）' },
  { key: 'keyword', value: '"login"', desc: '关键字（payloads 常用）' },
]

export const CEL_SNIPPETS = [
  { label: '状态码 200', value: 'response.status == 200' },
  { label: 'Body 包含', value: 'response.body.ibcontains(b"keyword")' },
  { label: 'Body 正则', value: '"pattern".bmatches(response.body)' },
  { label: 'Server 头', value: 'response.headers["server"].contains("nginx")' },
  { label: '原始头包含', value: 'response.raw_header.ibcontains(b"Server:")' },
  { label: 'Favicon', value: 'response.icon_hash == "1236214049"' },
]

export const REQUEST_FIELDS = [
  'request.url.scheme',
  'request.url.host',
  'request.url.domain',
  'request.url.path',
  'request.method',
  'request.headers',
  'request.body',
]

export const RESPONSE_FIELDS = [
  'response.status',
  'response.body',
  'response.headers',
  'response.raw_header',
  'response.icon_hash',
  'response.latency',
]

export const VAR_USAGE_TIP =
  'set 中填写 CEL 表达式求值结果；在 path / body / host / data 中用 {{变量名}} 引用（例如 path: "/{{num}}.php"）'

export interface VarTemplate {
  id: string
  title: string
  category: 'request' | 'response' | 'set'
  summary: string
  fields: { name: string; type: string; desc: string }[]
  sampleRaw?: string
  celExamples?: string[]
}

export const VAR_TEMPLATES: VarTemplate[] = [
  {
    id: 'request',
    title: 'request 请求对象',
    category: 'request',
    summary: '每条 rule 执行后注入 varMap，可在 CEL 表达式中引用',
    fields: [
      { name: 'request.method', type: 'string', desc: 'HTTP 方法，如 GET / POST' },
      { name: 'request.url.scheme', type: 'string', desc: '协议 http 或 https' },
      { name: 'request.url.host', type: 'string', desc: '主机名含端口，如 example.com:443' },
      { name: 'request.url.domain', type: 'string', desc: '根域名' },
      { name: 'request.url.path', type: 'string', desc: '请求路径' },
      { name: 'request.headers', type: 'map', desc: '请求头键值对' },
      { name: 'request.body', type: 'bytes', desc: '请求体原始字节' },
      { name: 'request.raw', type: 'bytes', desc: '完整 HTTP 请求报文' },
    ],
    sampleRaw: `GET /admin/login HTTP/1.1\r
Host: example.com\r
User-Agent: GXX-Finger/1.0\r
Accept: */*\r
\r
`,
    celExamples: [
      'request.method == "GET"',
      'request.url.path.contains("/admin")',
      'request.headers["user-agent"].contains("GXX")',
    ],
  },
  {
    id: 'response',
    title: 'response 响应对象',
    category: 'response',
    summary: 'HTTP 响应注入 varMap，匹配器与 CEL 最常用',
    fields: [
      { name: 'response.status', type: 'int', desc: 'HTTP 状态码，如 200 / 404' },
      { name: 'response.body', type: 'bytes', desc: '响应体原始字节' },
      { name: 'response.headers', type: 'map', desc: '响应头（小写 key）' },
      { name: 'response.raw_header', type: 'bytes', desc: '原始响应头（含 status line）' },
      { name: 'response.icon_hash', type: 'string', desc: 'Favicon mmh3 hash' },
      { name: 'response.latency', type: 'int', desc: '请求耗时（毫秒）' },
      { name: 'response.raw', type: 'bytes', desc: '完整 HTTP 响应报文' },
    ],
    sampleRaw: `HTTP/1.1 200 OK\r
Content-Type: text/html; charset=utf-8\r
Server: nginx\r
Content-Length: 1234\r
\r
<!DOCTYPE html><html>...</html>`,
    celExamples: [
      'response.status == 200',
      'response.body.ibcontains(b"login")',
      '"nginx".bmatches(response.body)',
      'response.headers["server"].contains("nginx")',
      'response.icon_hash == "1236214049"',
    ],
  },
  {
    id: 'set-vars',
    title: 'set 自定义变量',
    category: 'set',
    summary: '在 YAML set 块定义，path/body 中用 {{name}} 引用',
    fields: SET_VAR_PRESETS.map((p) => ({
      name: p.key,
      type: 'CEL → string/bytes',
      desc: `${p.desc}：${p.value}`,
    })),
    celExamples: [
      'set:\n  num: randomInt(800000000, 1000000000)\n  hostname: request.url.host',
      'path: "/{{num}}.php"   # 引用 set 变量',
    ],
  },
]

/** 产品声明 info.product 的取值与说明，与引擎的标准格式校验一致。 */
export interface OptionHint {
  value: string
  label: string
}

export const PRODUCT_CATEGORIES: OptionHint[] = [
  { value: 'application', label: 'application 应用系统' },
  { value: 'middleware', label: 'middleware 中间件' },
  { value: 'framework', label: 'framework 开发框架' },
  { value: 'operating-system', label: 'operating-system 操作系统' },
  { value: 'cms', label: 'cms 内容管理系统' },
  { value: 'database', label: 'database 数据库' },
  { value: 'web-server', label: 'web-server Web 服务器' },
  { value: 'security', label: 'security 安全产品' },
  { value: 'library', label: 'library 组件库' },
  { value: 'hosting-panel', label: 'hosting-panel 主机面板' },
  { value: 'device', label: 'device 设备' },
  { value: 'network-device', label: 'network-device 网络设备' },
  { value: 'iot', label: 'iot 物联网' },
  { value: 'other', label: 'other 其他' },
]

export const PRODUCT_IDENTITIES: OptionHint[] = [
  { value: 'product', label: 'product 命中即确认是这个产品' },
  { value: 'signal', label: 'signal 技术线索（语言、前端库、默认页面、通用特征）' },
]

export const PRODUCT_ASSURANCES: OptionHint[] = [
  { value: 'inferred', label: 'inferred 由规则名称与特征推断' },
  { value: 'verified', label: 'verified 厂商与产品已确认，并有官方参考链接' },
]

export const PRODUCT_TIP =
  '产品标识写成“厂商段.产品段”（小写字母、数字与连字符，如 weaver.e-cology）；厂商不确定时留空；同一产品的多条规则声明须完全相同。verified 至少需要一个官方参考链接。'

export const SERVICE_TIP = 'TCP/UDP 规则必须声明识别的服务：协议名、传输层（tcp/udp）与常见端口；HTTP 规则可以不填。'
