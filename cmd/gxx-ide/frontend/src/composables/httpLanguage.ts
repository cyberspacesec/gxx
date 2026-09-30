/**
 * HTTP 报文语言检测工具。
 *
 * 两类编辑器场景：
 * 1. 完整请求 / 响应原始报文（含 start-line + headers + body）
 *    → 使用自定义 `http` 语言（在 `monaco.ts` 注册）整体上色。
 * 2. 仅 body 文本（已剥离 headers，例如 ResponseView 的「Body」tab）
 *    → 根据 Content-Type / 内容嗅探落到 `json` / `html` / `xml` / `plaintext`。
 *
 * 两个分支分别由 {@link pickHttpRawLanguage} 与 {@link detectHttpBodyLanguage} 处理。
 */

/** Monaco 报文场景使用的语言集合。 */
export type HttpEditorLanguage = 'html' | 'json' | 'xml' | 'plaintext' | 'http'

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'] as const

/** 把 CRLF/CR 统一成 LF，避免后续 split 误判。 */
function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

/** 沿首个空行把 HTTP 报文切成 header / body。 */
function splitHttpPacket(raw: string): { header: string; body: string } {
  const normalized = normalizeNewlines(raw)
  const idx = normalized.indexOf('\n\n')
  if (idx < 0) return { header: normalized, body: '' }
  return {
    header: normalized.slice(0, idx),
    body: normalized.slice(idx + 2),
  }
}

/** 从 header 区域抽 `Content-Type`（仅 MIME，去掉 charset 等参数）。 */
function contentTypeFromHeader(header: string): string {
  const match = header.match(/^content-type:\s*(.+)$/im)
  return match?.[1]?.split(';')[0]?.trim().toLowerCase() ?? ''
}

/**
 * 判定 `raw` 是否为完整 HTTP 报文。
 *
 * 充分条件：首行匹配 `METHOD <SP> URI <SP> HTTP/x.y`（请求）
 * 或 `HTTP/x.y <SP> STATUS …`（响应）；用于决定是否用 `http` 语言整体高亮。
 */
export function isHttpRawPacket(raw: string): boolean {
  if (!raw) return false
  const firstLine = normalizeNewlines(raw).split('\n', 1)[0] ?? ''
  if (/^HTTP\/[0-9.]+\s+\d{3}\b/.test(firstLine)) return true
  for (const m of HTTP_METHODS) {
    if (firstLine.startsWith(`${m} `) && /\bHTTP\/[0-9.]+\s*$/.test(firstLine)) {
      return true
    }
  }
  return false
}

/**
 * 选择「整段原始报文」编辑器使用的语言。
 *
 * - 是完整报文 → `http`
 * - 否则回落到 body 嗅探（兼容只有 body 时直接复用此函数）
 */
export function pickHttpRawLanguage(raw: string): HttpEditorLanguage {
  if (isHttpRawPacket(raw)) return 'http'
  return detectHttpBodyLanguage(raw)
}

/**
 * 仅 body 场景的语言嗅探：优先看 Content-Type，其次看 body 起始字符。
 *
 * 返回 `'plaintext'` 时调用方应当用 plaintext 语言。
 */
export function detectHttpBodyLanguage(raw: string): HttpEditorLanguage {
  const { header, body } = splitHttpPacket(raw)
  const sample = body.trimStart()
  if (!sample) return 'plaintext'

  const ct = contentTypeFromHeader(header)
  if (ct.includes('json') || sample.startsWith('{') || sample.startsWith('[')) return 'json'
  if (ct.includes('html') || sample.startsWith('<!') || /<html/i.test(sample)) return 'html'
  if (ct.includes('xml') || sample.startsWith('<?xml')) return 'xml'
  return 'plaintext'
}

/**
 * 根据语言与 body 形态决定是否自动折行。
 *
 * HTML body 经常是「一整行的压缩 HTML」，开启折行会破坏视觉；其余场景默认折行。
 */
export function httpBodyWordWrap(raw: string, language: HttpEditorLanguage): 'on' | 'off' {
  if (language !== 'html') return 'on'
  const { body } = splitHttpPacket(raw)
  return body.length > 0 && !body.includes('\n') ? 'off' : 'on'
}
