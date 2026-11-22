import { parse as parseYaml, stringify as stringifyYaml } from 'yaml'

export type MatchPart = 'status' | 'body' | 'header' | 'raw_header'
export type MatchType = 'regex' | 'contains' | 'icontains' | 'status_eq' | 'header_contains'

export interface MatcherFormItem {
  type: MatchType
  part: MatchPart
  headerName: string
  value: string
}

export interface HeaderFormItem {
  key: string
  value: string
}

export interface SetVarFormItem {
  key: string
  value: string
}

export interface PayloadVarFormItem {
  key: string
  value: string
}

export interface PayloadGroupFormItem {
  key: string
  vars: PayloadVarFormItem[]
}

export interface PayloadsFormModel {
  enabled: boolean
  continue: boolean
  groups: PayloadGroupFormItem[]
}

export type RequestType = 'http' | 'tcp' | 'udp'

export interface RuleFormItem {
  key: string
  requestType: RequestType
  method: string
  path: string
  body: string
  host: string
  data: string
  headers: HeaderFormItem[]
  followRedirects: boolean
  expressionMode: 'matchers' | 'advanced'
  matchers: MatcherFormItem[]
  matcherLogic: 'and' | 'or'
  expression: string
  // 表单没有对应控件的字段（raw、data-type、read-size、output 等）原样保留，
  // 在表单与 YAML 之间往返时不丢失。
  requestExtra: Record<string, unknown>
  ruleExtra: Record<string, unknown>
}

export type FinalLogic = 'and' | 'or' | 'custom'

/**
 * 产品声明（info.product）。列表字段在表单中以文本编辑：tags 用逗号分隔，其余每行一个。
 * declared 表示源 YAML 已有 product 块；新建规则在填写产品标识或名称后才写出该块。
 */
export interface ProductFormModel {
  declared: boolean
  id: string
  name: string
  vendor: string
  category: string
  identity: string
  assurance: string
  tags: string
  aliases: string
  cpe: string
  references: string
  description: string
  // 表单未展示的键原样保留。
  extra: Record<string, unknown>
}

/** 服务声明（info.services 的一项）；ports 以逗号分隔编辑。 */
export interface ServiceFormItem {
  protocol: string
  transport: 'tcp' | 'udp'
  ports: string
  extra: Record<string, unknown>
}

export interface FingerFormModel {
  id: string
  info: {
    name: string
    author: string
    verified: boolean
    description: string
    reference: string
    tags: string
    created: string
    severity: string
    product: ProductFormModel
    services: ServiceFormItem[]
    // 表单未展示的元信息字段（metadata、classification、affected、solutions 等）。
    extra: Record<string, unknown>
  }
  setVars: SetVarFormItem[]
  payloads: PayloadsFormModel
  rules: RuleFormItem[]
  finalLogic: FinalLogic
  expression: string
}

export function todayString(): string {
  const d = new Date()
  return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`
}

export function defaultMatcher(): MatcherFormItem {
  return { type: 'contains', part: 'body', headerName: 'server', value: '' }
}

export function defaultRule(key = 'r0'): RuleFormItem {
  return {
    key,
    requestType: 'http',
    method: 'GET',
    path: '/',
    body: '',
    host: '',
    data: '',
    headers: [],
    followRedirects: true,
    expressionMode: 'matchers',
    matchers: [{ type: 'status_eq', part: 'status', headerName: '', value: '200' }],
    matcherLogic: 'and',
    expression: 'response.status == 200',
    requestExtra: {},
    ruleExtra: {},
  }
}

export function buildFinalExpression(rules: RuleFormItem[], logic: FinalLogic): string {
  if (logic === 'custom') return ''
  const joiner = logic === 'or' ? ' || ' : ' && '
  return rules.map((r) => `${r.key.trim() || 'r0'}()`).join(joiner)
}

export function detectFinalLogic(expression: string, ruleKeys: string[]): FinalLogic {
  const trimmed = expression.trim()
  if (!trimmed || ruleKeys.length === 0) return 'and'
  const andExpr = buildFinalExpression(ruleKeys.map((k) => ({ key: k } as RuleFormItem)), 'and')
  const orExpr = buildFinalExpression(ruleKeys.map((k) => ({ key: k } as RuleFormItem)), 'or')
  if (trimmed === andExpr) return 'and'
  if (trimmed === orExpr) return 'or'
  return 'custom'
}

export function defaultProduct(): ProductFormModel {
  return {
    declared: false,
    id: '',
    name: '',
    vendor: '',
    category: 'application',
    identity: 'product',
    assurance: 'inferred',
    tags: '',
    aliases: '',
    cpe: '',
    references: '',
    description: '',
    extra: {},
  }
}

export function defaultService(): ServiceFormItem {
  return { protocol: '', transport: 'tcp', ports: '', extra: {} }
}

export function defaultFingerForm(): FingerFormModel {
  return {
    id: 'new-rule-id',
    info: {
      name: '',
      author: '',
      verified: false,
      description: '',
      reference: '',
      tags: '',
      created: todayString(),
      severity: 'info',
      product: defaultProduct(),
      services: [],
      extra: {},
    },
    setVars: [],
    payloads: { enabled: false, continue: true, groups: [] },
    rules: [defaultRule('r0')],
    finalLogic: 'and',
    expression: 'r0()',
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function escapeStr(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

function bytesLiteral(s: string): string {
  return `b"${escapeStr(s)}"`
}

export function compileMatchers(matchers: MatcherFormItem[], logic: 'and' | 'or'): string {
  const parts = matchers.map((m) => compileMatcher(m)).filter((p) => p && p !== 'true')
  if (parts.length === 0) return 'true'
  if (parts.length === 1) return parts[0]
  const join = logic === 'and' ? ' && ' : ' || '
  return `(${parts.join(join)})`
}

export function compileMatcher(m: MatcherFormItem): string {
  const val = m.value.trim()
  if (!val && m.type !== 'status_eq') return 'true'

  switch (m.part) {
    case 'status':
      return `response.status == ${Number(val) || 0}`
    case 'body':
      if (m.type === 'regex') return `"${escapeStr(val)}".bmatches(response.body)`
      if (m.type === 'icontains') return `response.body.ibcontains(${bytesLiteral(val)})`
      return `response.body.bcontains(${bytesLiteral(val)})`
    case 'header': {
      const hk = (m.headerName || 'server').toLowerCase()
      return `response.headers["${hk}"].contains("${escapeStr(val)}")`
    }
    case 'raw_header':
      if (m.type === 'regex') return `"${escapeStr(val)}".bmatches(response.raw_header)`
      if (m.type === 'icontains') return `response.raw_header.ibcontains(${bytesLiteral(val)})`
      return `response.raw_header.bcontains(${bytesLiteral(val)})`
    default:
      return 'true'
  }
}

export function ruleExpression(rule: RuleFormItem): string {
  if (rule.expressionMode === 'advanced') {
    return rule.expression.trim() || 'true'
  }
  return compileMatchers(rule.matchers, rule.matcherLogic)
}

function parseMapSlice(raw: unknown): SetVarFormItem[] {
  const items: SetVarFormItem[] = []
  if (Array.isArray(raw)) {
    for (const entry of raw) {
      const rec = asRecord(entry)
      if (!rec) continue
      const key = asString(rec.Key ?? rec.key)
      const val = rec.Value ?? rec.value
      if (key) items.push({ key, value: asString(val) })
    }
    return items
  }
  const obj = asRecord(raw)
  if (!obj) return items
  for (const [key, val] of Object.entries(obj)) {
    items.push({ key, value: asString(val) })
  }
  return items
}

function parsePayloads(raw: unknown): PayloadsFormModel {
  const empty: PayloadsFormModel = { enabled: false, continue: true, groups: [] }
  const root = asRecord(raw)
  if (!root) return empty
  const groupsRaw = asRecord(root.payloads) ?? root
  const groups: PayloadGroupFormItem[] = []
  for (const [key, val] of Object.entries(groupsRaw)) {
    if (key === 'continue') continue
    groups.push({ key, vars: parseMapSlice(val).map((v) => ({ key: v.key, value: v.value })) })
  }
  return {
    enabled: groups.length > 0,
    continue: root.continue !== false,
    groups,
  }
}

function parseHeaders(raw: unknown): HeaderFormItem[] {
  const obj = asRecord(raw)
  if (!obj) return []
  return Object.entries(obj).map(([key, value]) => ({ key, value: asString(value) }))
}

function tryParseMatchersFromExpression(expr: string): {
  matchers: MatcherFormItem[]
  logic: 'and' | 'or'
  mode: 'matchers' | 'advanced'
} {
  const trimmed = expr.trim()
  if (!trimmed) {
    return { matchers: [defaultMatcher()], logic: 'and', mode: 'matchers' }
  }

  const logic: 'and' | 'or' = trimmed.includes('||') ? 'or' : 'and'
  const matchers: MatcherFormItem[] = []

  const statusRe = /response\.status\s*==\s*(\d+)/g
  let m: RegExpExecArray | null
  while ((m = statusRe.exec(trimmed)) !== null) {
    matchers.push({ type: 'status_eq', part: 'status', headerName: '', value: m[1] })
  }

  const bcontainsRe = /response\.body\.bcontains\(\s*b"((?:\\.|[^"\\])*)"\s*\)/g
  while ((m = bcontainsRe.exec(trimmed)) !== null) {
    matchers.push({
      type: 'contains',
      part: 'body',
      headerName: '',
      value: m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
    })
  }

  const ibcontainsRe = /response\.body\.ibcontains\(\s*b"((?:\\.|[^"\\])*)"\s*\)/g
  while ((m = ibcontainsRe.exec(trimmed)) !== null) {
    matchers.push({
      type: 'icontains',
      part: 'body',
      headerName: '',
      value: m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
    })
  }

  const headerRe = /response\.headers\["([^"]+)"\]\.contains\("((?:\\.|[^"\\])*)"\)/g
  while ((m = headerRe.exec(trimmed)) !== null) {
    matchers.push({
      type: 'header_contains',
      part: 'header',
      headerName: m[1],
      value: m[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
    })
  }

  const bmatchesRe = /"((?:\\.|[^"\\])*)"\.bmatches\(response\.body\)/g
  while ((m = bmatchesRe.exec(trimmed)) !== null) {
    matchers.push({
      type: 'regex',
      part: 'body',
      headerName: '',
      value: m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
    })
  }

  if (matchers.length > 0) {
    return { matchers, logic, mode: 'matchers' }
  }
  return { matchers: [defaultMatcher()], logic: 'and', mode: 'advanced' }
}

const INFO_FIELDS = ['name', 'author', 'verified', 'description', 'reference', 'tags', 'created', 'severity', 'product', 'services']
const PRODUCT_FIELDS = ['id', 'name', 'vendor', 'category', 'identity', 'assurance', 'tags', 'aliases', 'cpe', 'references', 'description']
const SERVICE_FIELDS = ['protocol', 'transport', 'ports']

function listText(value: unknown, separator: string): string {
  if (Array.isArray(value)) return value.map((item) => String(item)).join(separator)
  return typeof value === 'string' ? value : ''
}

function splitList(text: string, separator: RegExp): string[] {
  return text
    .split(separator)
    .map((item) => item.trim())
    .filter(Boolean)
}

function parseProduct(raw: unknown): ProductFormModel {
  const product = asRecord(raw)
  if (!product) return defaultProduct()
  const defaults = defaultProduct()
  return {
    declared: true,
    id: asString(product.id),
    name: asString(product.name),
    vendor: asString(product.vendor),
    category: asString(product.category, defaults.category),
    identity: asString(product.identity, defaults.identity),
    assurance: asString(product.assurance, defaults.assurance),
    tags: listText(product.tags, ', '),
    aliases: listText(product.aliases, '\n'),
    cpe: listText(product.cpe, '\n'),
    references: listText(product.references, '\n'),
    description: asString(product.description),
    extra: extraFields(product, PRODUCT_FIELDS),
  }
}

function parseServices(raw: unknown): ServiceFormItem[] {
  if (!Array.isArray(raw)) return []
  return raw.map((item): ServiceFormItem => {
    const service = asRecord(item) ?? {}
    return {
      protocol: asString(service.protocol),
      transport: asString(service.transport) === 'udp' ? 'udp' : 'tcp',
      ports: listText(service.ports, ', '),
      extra: extraFields(service, SERVICE_FIELDS),
    }
  })
}

/** 产品声明按标准字段顺序写出，可选项为空时省略。 */
function buildProduct(product: ProductFormModel): Record<string, unknown> | null {
  if (!product.declared && !product.id.trim() && !product.name.trim()) return null
  const result: Record<string, unknown> = { id: product.id.trim(), name: product.name.trim() }
  if (product.vendor.trim()) result.vendor = product.vendor.trim()
  result.category = product.category
  result.identity = product.identity
  result.assurance = product.assurance
  const lists: [string, string[]][] = [
    ['tags', splitList(product.tags, /[,，\s]+/)],
    ['aliases', splitList(product.aliases, /\r?\n/)],
    ['cpe', splitList(product.cpe, /\r?\n/)],
    ['references', splitList(product.references, /\r?\n/)],
  ]
  for (const [key, values] of lists) {
    if (values.length) result[key] = values
  }
  if (product.description.trim()) result.description = product.description.trim()
  return { ...result, ...product.extra }
}

function buildServices(services: ServiceFormItem[]): Record<string, unknown>[] {
  return services
    .filter((service) => service.protocol.trim() || service.ports.trim())
    .map((service) => ({
      protocol: service.protocol.trim(),
      transport: service.transport,
      ports: splitList(service.ports, /[,，\s]+/).map((port) => Number(port)).filter((port) => Number.isInteger(port)),
      ...service.extra,
    }))
}
const RULE_FIELDS = ['request', 'expression']
const REQUEST_FIELDS = ['type', 'method', 'path', 'body', 'headers', 'follow_redirects', 'host', 'data']

/** 返回 record 中表单没有对应控件的字段。 */
function extraFields(record: Record<string, unknown>, known: string[]): Record<string, unknown> {
  const extra: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (!known.includes(key)) extra[key] = value
  }
  return extra
}

/**
 * 归一化请求类型。引擎只实现 http / tcp / udp，TLS 由 host 的协议前缀决定；
 * 旧写法 `type: ssl` / `type: tls` 等价于 TCP 加 `ssl://` 前缀，其余未知类型
 * 按 TCP 展示，保存后由引擎在加载时校验。
 */
export function normalizeRequestType(rawType: string, host: string): { type: RequestType; host: string } {
  const type = rawType.trim().toLowerCase()
  if (type === '' || type === 'http') return { type: 'http', host }
  if (type === 'udp') return { type: 'udp', host }
  if ((type === 'ssl' || type === 'tls') && host && !host.includes('://')) {
    return { type: 'tcp', host: `ssl://${host}` }
  }
  return { type: 'tcp', host }
}

function parseRules(rulesRaw: unknown): RuleFormItem[] {
  const rules: RuleFormItem[] = []
  const pushRule = (key: string, val: unknown) => {
    const rule = asRecord(val) ?? {}
    const req = asRecord(rule.request) ?? {}
    const expr = asString(rule.expression, 'true')
    const parsed = tryParseMatchersFromExpression(expr)
    const transport = normalizeRequestType(asString(req.type), asString(req.host))
    rules.push({
      key,
      requestType: transport.type,
      method: asString(req.method, 'GET').toUpperCase(),
      path: asString(req.path, '/'),
      body: asString(req.body),
      host: transport.host,
      data: asString(req.data),
      headers: parseHeaders(req.headers),
      followRedirects: req.follow_redirects !== false,
      expressionMode: parsed.mode,
      matchers: parsed.matchers,
      matcherLogic: parsed.logic,
      expression: expr,
      requestExtra: extraFields(req, REQUEST_FIELDS),
      ruleExtra: extraFields(rule, RULE_FIELDS),
    })
  }

  if (Array.isArray(rulesRaw)) {
    for (const item of rulesRaw) {
      const map = asRecord(item)
      if (!map) continue
      for (const [key, val] of Object.entries(map)) pushRule(key, val)
    }
  } else {
    const rulesObj = asRecord(rulesRaw)
    if (rulesObj) {
      for (const [key, val] of Object.entries(rulesObj)) pushRule(key, val)
    }
  }
  return rules.length ? rules : [defaultRule()]
}

export function yamlToForm(content: string): FingerFormModel {
  const doc = parseYaml(content)
  const root = asRecord(doc)
  if (!root) return defaultFingerForm()

  const info = asRecord(root.info) ?? {}
  const refs = info.reference
  let reference = ''
  if (Array.isArray(refs)) reference = refs.map((r) => String(r)).join('\n')
  else if (typeof refs === 'string') reference = refs

  const rules = parseRules(root.rules)
  const ruleKeys = rules.map((r) => r.key)
  let expression = asString(root.expression, '')
  if (!expression && ruleKeys.length === 1) expression = `${ruleKeys[0]}()`
  if (!expression && ruleKeys.length > 1) expression = buildFinalExpression(rules, 'and')
  const finalLogic = detectFinalLogic(expression, ruleKeys)

  return {
    id: asString(root.id, 'new-rule-id'),
    info: {
      name: asString(info.name),
      author: asString(info.author),
      verified: Boolean(info.verified),
      description: asString(info.description),
      reference,
      tags: asString(info.tags),
      created: asString(info.created, todayString()),
      severity: asString(info.severity, 'info'),
      product: parseProduct(info.product),
      services: parseServices(info.services),
      extra: extraFields(info, INFO_FIELDS),
    },
    setVars: parseMapSlice(root.set),
    payloads: parsePayloads(root.payloads),
    rules,
    finalLogic,
    expression,
  }
}

function buildRequest(rule: RuleFormItem): Record<string, unknown> {
  const req: Record<string, unknown> = {}
  if (rule.requestType !== 'http') req.type = rule.requestType

  if (rule.requestType === 'http') {
    req.method = (rule.method || 'GET').toUpperCase()
    req.path = rule.path || '/'
    if (rule.body) req.body = rule.body
    if (rule.headers.length) {
      const headers: Record<string, string> = {}
      for (const h of rule.headers) {
        if (h.key.trim()) headers[h.key.trim()] = h.value
      }
      if (Object.keys(headers).length) req.headers = headers
    }
    if (!rule.followRedirects) req.follow_redirects = false
  } else {
    if (rule.host) req.host = rule.host
    if (rule.data) req.data = rule.data
  }
  return { ...req, ...rule.requestExtra }
}

function buildInfoBlock(form: FingerFormModel, refs: string[]): Record<string, unknown> {
  const info: Record<string, unknown> = {
    name: form.info.name,
    author: form.info.author,
    verified: form.info.verified,
  }
  if (form.info.description.trim()) info.description = form.info.description.trim()
  if (refs.length) info.reference = refs
  if (form.info.tags.trim()) info.tags = form.info.tags.trim()
  if (form.info.created.trim()) info.created = form.info.created.trim()
  if (form.info.severity && form.info.severity !== 'info') info.severity = form.info.severity
  const product = buildProduct(form.info.product)
  if (product) info.product = product
  const services = buildServices(form.info.services)
  if (services.length) info.services = services
  return { ...info, ...form.info.extra }
}

export function formToYaml(form: FingerFormModel): string {
  const refs = form.info.reference
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)

  const doc: Record<string, unknown> = {
    id: form.id.trim() || 'new-rule-id',
    info: buildInfoBlock(form, refs),
  }

  if (form.setVars.length) {
    const setObj: Record<string, string> = {}
    for (const v of form.setVars) {
      if (v.key.trim()) setObj[v.key.trim()] = v.value
    }
    if (Object.keys(setObj).length) doc.set = setObj
  }

  if (form.payloads.enabled && form.payloads.groups.length) {
    const payloadMap: Record<string, Record<string, string>> = {}
    for (const g of form.payloads.groups) {
      if (!g.key.trim()) continue
      const vars: Record<string, string> = {}
      for (const v of g.vars) {
        if (v.key.trim()) vars[v.key.trim()] = v.value
      }
      payloadMap[g.key.trim()] = vars
    }
    if (Object.keys(payloadMap).length) {
      doc.payloads = { continue: form.payloads.continue, payloads: payloadMap }
    }
  }

  const rulesObj: Record<string, unknown> = {}
  for (const rule of form.rules) {
    const key = rule.key.trim() || 'r0'
    rulesObj[key] = {
      request: buildRequest(rule),
      expression: ruleExpression(rule),
      ...rule.ruleExtra,
    }
  }
  doc.rules = rulesObj
  doc.expression = form.expression.trim() || `${form.rules[0]?.key || 'r0'}()`

  return stringifyYaml(doc, {
    lineWidth: 0,
    defaultStringType: 'PLAIN',
    defaultKeyType: 'PLAIN',
  }).trimEnd() + '\n'
}

export function nextRuleKey(rules: RuleFormItem[]): string {
  const used = new Set(rules.map((r) => r.key))
  for (let i = 0; i < 100; i++) {
    const key = `r${i}`
    if (!used.has(key)) return key
  }
  return `r${rules.length}`
}

export function buildSavePath(rootDir: string, id: string): string {
  const safe = (id.trim() || 'new-rule-id').replace(/[^\w.-]+/g, '-')
  return `${rootDir.replace(/[/\\]+$/, '')}/${safe}.yaml`
}

export const MATCH_PART_LABELS: Record<MatchPart, string> = {
  status: '状态码',
  body: '响应体',
  header: '响应头',
  raw_header: '原始响应头',
}

export const MATCH_TYPE_LABELS: Record<MatchType, string> = {
  regex: '正则表达式',
  contains: '包含（区分大小写）',
  icontains: '包含（忽略大小写）',
  status_eq: '等于状态码',
  header_contains: '响应头包含',
}
