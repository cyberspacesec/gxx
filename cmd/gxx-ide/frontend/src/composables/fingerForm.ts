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

export interface RuleFormItem {
  key: string
  requestType: 'http' | 'tcp' | 'udp' | 'ssl'
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
}

export type FinalLogic = 'and' | 'or' | 'custom'

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

function parseRules(rulesRaw: unknown): RuleFormItem[] {
  const rules: RuleFormItem[] = []
  const pushRule = (key: string, val: unknown) => {
    const rule = asRecord(val) ?? {}
    const req = asRecord(rule.request) ?? {}
    const expr = asString(rule.expression, 'true')
    const parsed = tryParseMatchersFromExpression(expr)
    rules.push({
      key,
      requestType: (asString(req.type, 'http') as RuleFormItem['requestType']) || 'http',
      method: asString(req.method, 'GET').toUpperCase(),
      path: asString(req.path, '/'),
      body: asString(req.body),
      host: asString(req.host),
      data: asString(req.data),
      headers: parseHeaders(req.headers),
      followRedirects: req.follow_redirects !== false,
      expressionMode: parsed.mode,
      matchers: parsed.matchers,
      matcherLogic: parsed.logic,
      expression: expr,
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
  return req
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
  return info
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
  return `${rootDir.replace(/[/\\]+$/, '')}/${safe}.yml`
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
