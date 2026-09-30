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
