import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import ts from 'typescript'
import { parse } from 'yaml'

// 把表单模型的 TypeScript 源码转译为 ESM 后加载；输出放在 node_modules 下，
// 使其中的 `yaml` 依赖按正常规则解析，且不进入版本控制。
const root = fileURLToPath(new URL('..', import.meta.url))
const source = fs.readFileSync(path.join(root, 'src/composables/fingerForm.ts'), 'utf8')
const output = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
}).outputText
const cacheDir = path.join(root, 'node_modules/.cache/gxx-tests')
fs.mkdirSync(cacheDir, { recursive: true })
const modulePath = path.join(cacheDir, 'fingerForm.mjs')
fs.writeFileSync(modulePath, output)
const { yamlToForm, formToYaml, normalizeRequestType, defaultFingerForm, buildSavePath } = await import(pathToFileURL(modulePath).href)

test('旧的 ssl 类型转换为 tcp 加 ssl:// 前缀', () => {
  assert.deepEqual(normalizeRequestType('ssl', '{{hostname}}:8443'), { type: 'tcp', host: 'ssl://{{hostname}}:8443' })
  assert.deepEqual(normalizeRequestType('TLS', 'example.com'), { type: 'tcp', host: 'ssl://example.com' })
  assert.deepEqual(normalizeRequestType('ssl', 'tls://example.com'), { type: 'tcp', host: 'tls://example.com' })
  assert.deepEqual(normalizeRequestType(' HTTP ', ''), { type: 'http', host: '' })
  assert.deepEqual(normalizeRequestType('', ''), { type: 'http', host: '' })
  assert.deepEqual(normalizeRequestType('UDP', 'example.com:53'), { type: 'udp', host: 'example.com:53' })
})

test('表单生成的请求类型只有引擎实现的 http、tcp、udp', () => {
  const yaml = formToYaml(
    yamlToForm(`id: legacy
info:
  name: legacy
rules:
  r0:
    request:
      type: ssl
      host: "{{hostname}}:8443"
      data: "ping"
    expression: response.raw.bcontains(b"pong")
expression: r0()
`),
  )
  const request = parse(yaml).rules.r0.request
  assert.equal(request.type, 'tcp')
  assert.equal(request.host, 'ssl://{{hostname}}:8443')
  assert.equal(request.data, 'ping')
})

test('表单没有控件的字段在往返后保留', () => {
  const original = `id: keep-fields
info:
  name: keep
  author: tester
  verified: true
  affected: "<= 1.0"
  classification:
    cve-id: CVE-2026-0001
rules:
  r0:
    request:
      type: tcp
      host: "[{{hostname}}]:22"
      data: "0a"
      data-type: hex
      read-size: 4096
      read-timeout: 3
      read-idle: 500
    expression: response.raw.bcontains(b"SSH-")
    output:
      product_version: '"1.0"'
  r1:
    request:
      raw: |
        GET /admin HTTP/1.1
        Host: {{hostname}}
    expression: response.status == 200
expression: r0() || r1()
`
  const roundTrip = parse(formToYaml(yamlToForm(original)))
  assert.deepEqual(roundTrip.info.classification, { 'cve-id': 'CVE-2026-0001' })
  assert.equal(roundTrip.info.affected, '<= 1.0')
  const request = roundTrip.rules.r0.request
  assert.equal(request['data-type'], 'hex')
  assert.equal(request['read-size'], 4096)
  assert.equal(request['read-timeout'], 3)
  assert.equal(request['read-idle'], 500)
  assert.deepEqual(roundTrip.rules.r0.output, { product_version: '"1.0"' })
  assert.match(roundTrip.rules.r1.request.raw, /^GET \/admin HTTP\/1\.1/)
  assert.equal(roundTrip.expression, 'r0() || r1()')
})

test('新建规则默认是 http 且不携带额外字段', () => {
  const yaml = parse(formToYaml(defaultFingerForm()))
  assert.deepEqual(yaml.rules.r0.request, { method: 'GET', path: '/' })
  assert.deepEqual(Object.keys(yaml.rules.r0), ['request', 'expression'])
})

const standardRule = `id: weaver-e-cology
info:
  name: 泛微 e-cology
  author: tester
  product:
    id: weaver.e-cology
    name: e-cology
    vendor: 泛微网络
    category: application
    identity: product
    assurance: verified
    tags: [oa]
    aliases: [泛微OA, ecology]
    references:
      - https://www.weaver.com.cn/
    custom-key: kept
  services:
    - protocol: ssh
      transport: tcp
      ports: [22, 2222]
  metadata:
    owner: {team: a}
rules:
  r0:
    request:
      method: GET
      path: /
    expression: response.body.ibcontains(b"ecology")
expression: r0()
`

test('产品、服务与附加元数据在表单往返后保留，字段按标准顺序写出', () => {
  const form = yamlToForm(standardRule)
  assert.equal(form.info.product.id, 'weaver.e-cology')
  assert.equal(form.info.product.aliases, '泛微OA\necology')
  assert.equal(form.info.services[0].ports, '22, 2222')
  const info = parse(formToYaml(form)).info
  assert.deepEqual(Object.keys(info.product), ['id', 'name', 'vendor', 'category', 'identity', 'assurance', 'tags', 'aliases', 'references', 'custom-key'])
  assert.deepEqual(info.product.aliases, ['泛微OA', 'ecology'])
  assert.deepEqual(info.product.references, ['https://www.weaver.com.cn/'])
  assert.deepEqual(info.services, [{ protocol: 'ssh', transport: 'tcp', ports: [22, 2222] }])
  assert.deepEqual(info.metadata, { owner: { team: 'a' } })
})

test('产品声明的可选项为空时不写出，列表文本按分隔符拆分', () => {
  const form = defaultFingerForm()
  form.info.product.id = 'acme.portal'
  form.info.product.name = 'Acme Portal'
  form.info.product.tags = 'oa, vpn，login'
  form.info.services.push({ protocol: '', transport: 'tcp', ports: '', extra: {} })
  const info = parse(formToYaml(form)).info
  assert.deepEqual(info.product, { id: 'acme.portal', name: 'Acme Portal', category: 'application', identity: 'product', assurance: 'inferred', tags: ['oa', 'vpn', 'login'] })
  assert.equal(info.services, undefined)
})

test('新建规则在填写产品前不写出 product，默认保存为 .yaml', () => {
  const form = defaultFingerForm()
  assert.deepEqual([form.info.product.category, form.info.product.identity, form.info.product.assurance], ['application', 'product', 'inferred'])
  assert.equal(parse(formToYaml(form)).info.product, undefined)
  assert.equal(buildSavePath('/library/', 'acme-portal'), '/library/acme-portal.yaml')
})
