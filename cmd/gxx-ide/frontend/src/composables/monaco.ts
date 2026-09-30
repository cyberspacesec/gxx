/**
 * Monaco 编辑器初始化辅助。
 *
 * 职责：
 * 1. 配置 Monaco worker 路径（通过 Vite 的 `?worker` 后缀加载分包 worker）。
 * 2. 注册自定义语言：
 *    - `cel` —— CEL 表达式（Monarch tokenizer）。
 *    - `http` —— HTTP 报文（通过 Shiki/TextMate grammar，与 VS Code 一致的精确高亮）。
 * 3. 为 YAML / CEL 编辑器提供 CEL 函数与变量字段自动补全。
 *
 * HTTP 高亮使用 `@shikijs/monaco` 集成 Shiki 的 TextMate grammar（来自 VS Code REST Client），
 * 支持 body 内嵌 JSON/XML/HTML 子语言高亮。
 */

import * as monaco from 'monaco-editor/esm/vs/editor/editor.api'
import 'monaco-editor/esm/vs/basic-languages/yaml/yaml.contribution'
import 'monaco-editor/esm/vs/language/json/monaco.contribution'
import jsonWorker from 'monaco-editor/esm/vs/language/json/json.worker?worker'
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'

let initialization: Promise<void> | undefined

const CEL_FUNCTIONS = [
  { label: 'icontains', detail: '(s, sub) string -> bool', insertText: 'icontains("$1")$0' },
  { label: 'substr', detail: '(s, start, length) -> string', insertText: 'substr($1, $2, $3)' },
  { label: 'replaceAll', detail: '(s, old, new) -> string', insertText: 'replaceAll("$1", "$2", "$3")' },
  { label: 'printable', detail: '(s) -> string', insertText: 'printable($1)' },
  { label: 'toUintString', detail: '(s, direction) -> string', insertText: 'toUintString($1, $2)' },
  { label: 'bcontains', detail: '(bytes, bytes) -> bool', insertText: 'bcontains(b"$1")' },
  { label: 'ibcontains', detail: '(bytes, bytes) -> bool', insertText: 'ibcontains(b"$1")' },
  { label: 'bstartsWith', detail: '(bytes, bytes) -> bool', insertText: 'bstartsWith(b"$1")' },
  { label: 'bmatches', detail: '(pattern, bytes) -> bool', insertText: 'bmatches("$1")' },
  { label: 'submatch', detail: '(pattern, string) -> map', insertText: 'submatch("$1")' },
  { label: 'bsubmatch', detail: '(pattern, bytes) -> map', insertText: 'bsubmatch("$1")' },
  { label: 'md5', detail: '(string) -> string', insertText: 'md5("$1")' },
  { label: 'base64', detail: '(string|bytes) -> string', insertText: 'base64($1)' },
  { label: 'base64Decode', detail: '(string|bytes) -> string', insertText: 'base64Decode($1)' },
  { label: 'urlencode', detail: '(string|bytes) -> string', insertText: 'urlencode($1)' },
  { label: 'urldecode', detail: '(string|bytes) -> string', insertText: 'urldecode($1)' },
  { label: 'hexdecode', detail: '(string) -> string', insertText: 'hexdecode($1)' },
  { label: 'faviconHash', detail: '(string|bytes) -> int', insertText: 'faviconHash($1)' },
  { label: 'randomInt', detail: '(min, max) -> int', insertText: 'randomInt($1, $2)' },
  { label: 'randomLowercase', detail: '(length) -> string', insertText: 'randomLowercase($1)' },
  { label: 'year', detail: '() -> string (4 位年份)', insertText: 'year(0)' },
  { label: 'shortyear', detail: '() -> string (2 位年份)', insertText: 'shortyear(0)' },
  { label: 'month', detail: '() -> string', insertText: 'month(0)' },
  { label: 'day', detail: '() -> string', insertText: 'day(0)' },
  { label: 'timestamp_second', detail: '() -> string', insertText: 'timestamp_second(0)' },
  { label: 'sleep', detail: '(seconds)', insertText: 'sleep($1)' },
]

const REQUEST_FIELDS = [
  'request.url.scheme', 'request.url.domain', 'request.url.host', 'request.url.port',
  'request.url.path', 'request.url.query', 'request.url.fragment',
  'request.method', 'request.headers', 'request.content_type',
  'request.body', 'request.raw', 'request.raw_header',
]

const RESPONSE_FIELDS = [
  'response.status', 'response.url.scheme', 'response.url.domain', 'response.url.host',
  'response.url.port', 'response.url.path', 'response.url.query',
  'response.headers', 'response.content_type', 'response.body',
  'response.raw', 'response.raw_header', 'response.icon_hash', 'response.latency',
]

/**
 * 初始化 Monaco（idempotent）。
 *
 * HTTP 高亮通过 Shiki TextMate grammar 实现（与 VS Code REST Client 一致），
 * 支持 body 中嵌入 JSON/XML/HTML 等子语言高亮。
 * CEL 仍用 Monarch tokenizer（Shiki 无 CEL grammar）。
 */
export function setupMonaco(): Promise<void> {
  initialization ??= initializeMonaco()
  return initialization
}

async function initializeMonaco() {

  ;(globalThis as typeof globalThis & {
    MonacoEnvironment?: { getWorker(workerId: string, label: string): Worker }
  }).MonacoEnvironment = {
    getWorker(_workerId: string, label: string): Worker {
      if (label === 'json') return new jsonWorker()
      return new editorWorker()
    },
  }

  // ── CEL 自定义语言（Monarch）──
  monaco.languages.register({ id: 'cel' })
  monaco.languages.setMonarchTokensProvider('cel', {
    keywords: ['true', 'false', 'null', 'in', 'has'],
    operators: ['==', '!=', '<=', '>=', '&&', '||', '!', '+', '-', '*', '/', '%'],
    symbols: /[=><!~?:&|+\-*/^%]+/,
    tokenizer: {
      root: [
        [/b"([^"\\]|\\.)*"/, 'string.bytes'],
        [/"([^"\\]|\\.)*"/, 'string'],
        [/'([^'\\]|\\.)*'/, 'string'],
        [/\b\d+(\.\d+)?\b/, 'number'],
        [/\b(true|false|null)\b/, 'keyword'],
        [/\b(in|has)\b/, 'keyword'],
        [/\b[a-zA-Z_][a-zA-Z0-9_]*\b/, {
          cases: {
            '@keywords': 'keyword',
            '@default': 'identifier',
          },
        }],
        [/@symbols/, 'operator'],
        [/\s+/, ''],
      ],
    },
  })

  // ── HTTP 语言通过 Shiki TextMate grammar 高亮 ──
  try {
    const { createHighlighterCore } = await import('shiki/core')
    const { createOnigurumaEngine } = await import('shiki/engine/oniguruma')
    const { shikiToMonaco } = await import('@shikijs/monaco')

    const highlighter = await createHighlighterCore({
      engine: createOnigurumaEngine(import('shiki/wasm')),
      themes: [import('shiki/themes/github-light.mjs'), import('shiki/themes/github-dark.mjs')],
      langs: [import('shiki/langs/http.mjs'), import('shiki/langs/json.mjs'), import('shiki/langs/xml.mjs'), import('shiki/langs/html.mjs'), import('shiki/langs/shellscript.mjs'), import('shiki/langs/css.mjs'), import('shiki/langs/javascript.mjs')],
    })

    monaco.languages.register({ id: 'http' })
    shikiToMonaco(highlighter, monaco)
  } catch {
    // Shiki 加载失败时回退到 Monarch tokenizer
    monaco.languages.register({ id: 'http' })
    monaco.languages.setMonarchTokensProvider('http', {
      defaultToken: '',
      tokenPostfix: '.http',
      tokenizer: {
        root: [
          [/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)(\s+)(\S+)(\s+)(HTTP\/[0-9.]+)\s*$/,
            ['keyword', '', 'string', '', 'type']],
          [/^(HTTP\/[0-9.]+)(\s+)(\d{3})(\s+)(.*)$/,
            ['type', '', 'number', '', 'string']],
          [/^([A-Za-z][A-Za-z0-9_-]*)(\s*:\s*)(.*)$/,
            ['variable', 'delimiter', 'string']],
          [/^\s*$/, { token: 'delimiter', next: '@body' }],
          [/.+/, ''],
        ],
        body: [[/.*/, 'string']],
      },
    })
  }

  const { isDark } = await import('./useTheme')
  monaco.editor.setTheme(isDark.value ? 'github-dark' : 'github-light')

  const { watch } = await import('vue')
  watch(isDark, (dark) => {
    monaco.editor.setTheme(dark ? 'github-dark' : 'github-light')
  })

  // ── CEL 自动补全 ──
  monaco.languages.registerCompletionItemProvider(['yaml', 'cel'], {
    triggerCharacters: ['.', 'r', 'b', 'i', '('],
    provideCompletionItems(model, position) {
      const word = model.getWordUntilPosition(position)
      const range = new monaco.Range(
        position.lineNumber, word.startColumn,
        position.lineNumber, word.endColumn,
      )

      const suggestions: monaco.languages.CompletionItem[] = []

      for (const fn of CEL_FUNCTIONS) {
        suggestions.push({
          label: fn.label,
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: fn.insertText,
          insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
          detail: fn.detail,
          range,
        })
      }
      for (const field of [...REQUEST_FIELDS, ...RESPONSE_FIELDS]) {
        suggestions.push({
          label: field,
          kind: monaco.languages.CompletionItemKind.Field,
          insertText: field,
          detail: 'CEL 变量',
          range,
        })
      }
      for (let i = 0; i < 10; i++) {
        suggestions.push({
          label: `r${i}()`,
          kind: monaco.languages.CompletionItemKind.Function,
          insertText: `r${i}()`,
          detail: '子规则 ${i} 结果引用',
          range,
        })
      }

      return { suggestions }
    },
  })
}
