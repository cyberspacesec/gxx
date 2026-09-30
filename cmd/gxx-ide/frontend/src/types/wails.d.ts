// 给 wailsjs 自动生成的绑定提供 TS 声明。
// 实际类型由 `wails dev` / `wails build` 时根据 Go 结构体自动生成到 wailsjs/go 下。

declare module 'wailsjs/go/main/App' {
  export function SendRequest(opts: RequestOptions): Promise<RequestResponse>
  export function ValidateYAML(content: string): Promise<YAMLValidation>
  export function RunFingerprint(req: RunRequest): Promise<RunResult>
  export function EvaluateCEL(req: EvaluateCELRequest): Promise<EvaluateCELResult>
  export function ListFingerLibrary(rootDir: string, includeOutline: boolean): Promise<FingerFileMeta[]>
  export function LoadFingerYaml(path: string): Promise<string>
  export function SaveFingerYaml(path: string, content: string): Promise<void>
  export function DeleteFingerYaml(path: string): Promise<void>
  export function DefaultLibraryDir(): Promise<string>
}

declare module 'wailsjs/runtime/runtime' {
  export function LogPrint(message: string): void
  export function WindowSetTitle(title: string): void
  export function ClipboardSetText(text: string): Promise<boolean>
  export function ClipboardGetText(): Promise<string>
}

export interface RequestOptions {
  mode: 'url' | 'raw'
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

export interface CertSummary {
  subject: string
  issuer: string
  notBefore: string
  notAfter: string
  serialNumber: string
  signatureAlgorithm: string
  dnsNames: string[]
}

export interface RequestResponse {
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
  error: string
}

export interface YAMLError {
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

export interface YAMLValidation {
  valid: boolean
  errors: YAMLError[]
  outline?: FingerOutline | null
}

export interface RunRequest {
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

export interface RunResult {
  success: boolean
  finalExpression: string
  finalResult: boolean
  expressionError: string
  error: string
  rules: RuleRun[]
  variables: VarEntry[]
  fingerOutline?: FingerOutline | null
}

export interface EvaluateCELRequest {
  expression: string
  variables: Record<string, unknown>
}

export interface EvaluateCELResult {
  success: boolean
  result: string
  type: string
  error: string
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
