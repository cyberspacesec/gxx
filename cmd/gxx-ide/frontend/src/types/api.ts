// 与 Go 后端 internal/model 一一对应的 TypeScript 类型定义。

export type RequestMode = 'url' | 'raw'

export interface SendRequestInput {
  mode: RequestMode
  target: string
  method?: string
  headers?: Record<string, string>
  body?: string
  raw?: string
  useTls: boolean
  verifyTls: boolean
  followRedirects: boolean
  timeoutSeconds: number
  proxy?: string
}

export interface CertName {
  commonName?: string
  organization?: string[]
  organizationalUnit?: string[]
  country?: string[]
  province?: string[]
  locality?: string[]
}

export interface CertSummary {
  subject: CertName
  subjectDN: string
  issuer: CertName
  issuerDN: string
  notBefore: string
  notAfter: string
  valid: boolean
  serialNumber: string
  publicKeyAlgorithm: string
  publicKey?: string
  signatureAlgorithm: string
  version: number
  dnsNames?: string[]
  ipAddresses?: string[]
  emailAddresses?: string[]
  ocspServer?: string[]
  crlDistributionPoints?: string[]
}

export interface SendRequestOutput {
  status: number
  statusText: string
  headers: Record<string, string>
  rawHeader: string
  body: string
  bodyIsBase64: boolean
  bodyBytes: number
  latency: number
  iconHash: string
  title: string
  server: string
  certs: CertSummary[] | null
  finalUrl: string
  requestRaw: string
}

export interface ValidateYAMLInput {
  content: string
}

export interface YAMLValidationError {
  line: number
  column: number
  message: string
}

export interface RuleOutline {
  key: string
  type: string
  method: string
  path: string
  expression: string
}

export interface FingerOutline {
  id: string
  name: string
  author: string
  severity: string
  tags: string
  description: string
  expression: string
  ruleKeys: string[]
  rules: RuleOutline[]
  setVars: string[]
}

export interface ValidateYAMLOutput {
  valid: boolean
  errors: YAMLValidationError[]
  outline?: FingerOutline | null
}

export interface RunFingerprintInput {
  yaml: string
  target: string
  proxy?: string
  timeoutSeconds: number
  useTls: boolean
  verifyTls: boolean
  followRedirects: boolean
}

export interface RuleRun {
  key: string
  expression: string
  method: string
  path: string
  urlEvaluated: string
  requestRaw: string
  responseRaw: string
  statusCode: number
  latency: number
  result: boolean
  httpError: string
  celError: string
  nonBoolResult: boolean
}

export interface VarEntry {
  key: string
  type: string
  value: string
}

export interface RunFingerprintOutput {
  finalExpression: string
  finalResult: boolean
  expressionError: string
  rules: RuleRun[]
  variables: VarEntry[]
  fingerOutline?: FingerOutline | null
}

export interface EvaluateCELInput {
  expression: string
  variables: Record<string, unknown>
}

export interface EvaluateCELOutput {
  result: string
  type: string
}

export interface FingerFileMeta {
  path: string
  relPath: string
  name: string
  sizeBytes: number
  modifiedAt: string
  outline?: FingerOutline | null
  parseError?: string
}

export interface APIResponse<T = unknown> {
  code: number
  message: string
  data?: T
}
