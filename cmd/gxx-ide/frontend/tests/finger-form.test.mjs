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
const { yamlToForm, formToYaml, normalizeRequestType, defaultFingerForm } = await import(pathToFileURL(modulePath).href)

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
