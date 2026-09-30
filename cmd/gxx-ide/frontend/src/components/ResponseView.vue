<script setup lang="ts">
/**
 * 响应视图。
 *
 * 五个 tab：
 * - **Raw 响应**：start-line + headers + body 拼接的完整响应原文，使用 `http` 语言高亮。
 * - **Body**：仅 body，按 Content-Type 嗅探后落到 json / html / xml / plaintext。
 * - **Raw Header**：仅响应头，plaintext。
 * - **Request**：本次发出的完整请求原文，同样使用 `http` 语言高亮。
 * - **Certs**：TLS 证书链，列表展示，非 Monaco。
 *
 * 选择 Monaco 而非纯 `<pre>` 是因为大 body 需要虚拟滚动、查找、自动换行控制。
 */
import { computed, defineAsyncComponent, ref } from 'vue'
import type { CertName, SendRequestOutput } from '@/types/api'
import {
  httpBodyWordWrap,
  pickHttpRawLanguage,
  type HttpEditorLanguage,
} from '@/composables/httpLanguage'

const MonacoYamlEditor = defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))

const props = defineProps<{ response: SendRequestOutput }>()

type Tab = 'raw' | 'body' | 'headers' | 'request' | 'certs'
type BodyViewMode = 'utf8' | 'hex' | 'base64'

const activeTab = ref<Tab>('raw')
const bodyViewMode = ref<BodyViewMode>('utf8')
const prettyJson = ref(true)
const copyHint = ref('')

const bodyModes: { key: BodyViewMode; label: string }[] = [
  { key: 'utf8', label: 'UTF-8' },
  { key: 'hex', label: 'Hex' },
  { key: 'base64', label: 'Base64' },
]

function toHexView(text: string): string {
  const lines: string[] = []
  for (let offset = 0; offset < text.length; offset += 16) {
    const chunk = text.slice(offset, offset + 16)
    const hex = Array.from(chunk)
      .map((ch) => ch.charCodeAt(0).toString(16).padStart(2, '0'))
      .join(' ')
    const ascii = Array.from(chunk)
      .map((ch) => {
        const code = ch.charCodeAt(0)
        return code >= 0x20 && code <= 0x7e ? ch : '.'
      })
      .join('')
    const addr = offset.toString(16).padStart(8, '0')
    lines.push(`${addr}  ${hex.padEnd(47)}  |${ascii}|`)
  }
  return lines.join('\n')
}

const tabs: { key: Tab; label: string }[] = [
  { key: 'raw', label: 'Raw 响应' },
  { key: 'body', label: 'Body' },
  { key: 'headers', label: 'Raw Header' },
  { key: 'request', label: 'Request' },
  { key: 'certs', label: 'Certs' },
]

const certs = computed(() => props.response.certs ?? [])

function formatCertName(name: CertName | undefined, dnFallback?: string): string {
  if (!name && !dnFallback) return '—'
  if (name) {
    const parts: string[] = []
    if (name.commonName) parts.push(`CN=${name.commonName}`)
    if (name.organization?.length) parts.push(`O=${name.organization.join(', ')}`)
    if (name.organizationalUnit?.length) parts.push(`OU=${name.organizationalUnit.join(', ')}`)
    if (name.country?.length) parts.push(`C=${name.country.join(', ')}`)
    if (name.province?.length) parts.push(`ST=${name.province.join(', ')}`)
    if (name.locality?.length) parts.push(`L=${name.locality.join(', ')}`)
    if (parts.length > 0) return parts.join(', ')
  }
  return dnFallback || '—'
}

const contentType = computed(() => {
  const ct = props.response.headers?.['Content-Type'] ?? props.response.headers?.['content-type']
  return ct?.split(';')[0]?.trim() ?? ''
})

function decodedBody(): string {
  if (!props.response.body) return ''
  if (props.response.bodyIsBase64) {
    try {
      return atob(props.response.body)
    } catch {
      return '[二进制响应，无法解码为文本]'
    }
  }
  return props.response.body
}

function formatBody(text: string): string {
  if (!prettyJson.value || !text.trim()) return text
  const ct = contentType.value.toLowerCase()
  if (!ct.includes('json') && !text.trimStart().startsWith('{') && !text.trimStart().startsWith('[')) {
    return text
  }
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

const bodyText = computed(() => {
  const raw = decodedBody()
  switch (bodyViewMode.value) {
    case 'hex':
      return toHexView(raw)
    case 'base64':
      if (props.response.bodyIsBase64) return props.response.body
      try { return btoa(unescape(encodeURIComponent(raw))) } catch { return btoa(raw) }
    default:
      return formatBody(raw)
  }
})

const rawHeaderText = computed(() => normalizeNewlines(props.response.rawHeader ?? '').trimEnd())

function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
}

const fullRawResponse = computed(() => {
  const header = rawHeaderText.value
  const body = normalizeNewlines(decodedBody())
  if (!header && !body) return ''
  if (!header) return body
  if (!body) return `${header}\n`
  return `${header}\n\n${body}`
})

/** body 文本专用嗅探（已剥离 headers，因此不能复用 splitHttpPacket）。 */
function detectBodyLanguage(text: string): HttpEditorLanguage {
  const ct = contentType.value.toLowerCase()
  const sample = text.trimStart()
  if (ct.includes('json') || sample.startsWith('{') || sample.startsWith('[')) return 'json'
  if (ct.includes('html') || sample.startsWith('<!') || /<html/i.test(sample)) return 'html'
  if (ct.includes('xml') || sample.startsWith('<?xml')) return 'xml'
  return 'plaintext'
}

const editorContent = computed(() => {
  switch (activeTab.value) {
    case 'raw': return fullRawResponse.value
    case 'body': return bodyText.value
    case 'headers': return rawHeaderText.value
    case 'request': return normalizeNewlines(props.response.requestRaw || '')
    default: return ''
  }
})

const editorLanguage = computed<HttpEditorLanguage>(() => {
  if (activeTab.value === 'headers') return 'plaintext'
  // 请求 / 响应整体走 `http` 自定义语言（首行 + headers + body 三段都上色）
  if (activeTab.value === 'request' || activeTab.value === 'raw') {
    return pickHttpRawLanguage(editorContent.value)
  }
  if (activeTab.value === 'body') {
    if (bodyViewMode.value !== 'utf8') return 'plaintext'
    return detectBodyLanguage(editorContent.value)
  }
  return detectBodyLanguage(decodedBody())
})

const editorWordWrap = computed<'on' | 'off'>(() => {
  if (activeTab.value === 'request' || activeTab.value === 'raw') {
    return httpBodyWordWrap(editorContent.value, editorLanguage.value)
  }
  return 'on'
})

const editorTabs: Tab[] = ['raw', 'body', 'headers', 'request']

const showPrettyToggle = computed(() =>
  activeTab.value === 'body' && bodyViewMode.value === 'utf8' && (
    contentType.value.toLowerCase().includes('json')
    || decodedBody().trimStart().startsWith('{')
    || decodedBody().trimStart().startsWith('[')
  ),
)

const charCount = computed(() => editorContent.value.length)

/** HTTP 状态码 → CSS class，控制 status pill 配色。 */
const statusClass = computed<string>(() => {
  const s = props.response.status
  if (s >= 200 && s < 300) return 'ok'
  if (s >= 300 && s < 400) return 'redirect'
  if (s >= 400 && s < 500) return 'client'
  if (s >= 500) return 'server'
  return ''
})

async function copyCurrent() {
  const text = editorContent.value
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    copyHint.value = '已复制'
  } catch {
    copyHint.value = '复制失败'
  }
  window.setTimeout(() => { copyHint.value = '' }, 1600)
}
</script>

<template>
  <div class="response-view">
    <header class="meta">
      <div class="status">
        <span class="status-code" :class="statusClass">{{ response.status || '—' }}</span>
        <span class="status-text">{{ response.statusText }}</span>
      </div>
      <div class="meta-items">
        <span class="chip"><b>{{ response.latency }}</b> ms</span>
        <span class="chip"><b>{{ response.bodyBytes }}</b> bytes</span>
        <span v-if="contentType" class="chip ctype">{{ contentType }}</span>
        <span v-if="response.title" class="chip title">标题：{{ response.title }}</span>
        <span v-if="response.server" class="chip">Server：{{ response.server }}</span>
        <span v-if="response.iconHash" class="chip">favicon：{{ response.iconHash }}</span>
        <span v-if="response.finalUrl" class="chip title">URL：{{ response.finalUrl }}</span>
      </div>
    </header>

    <div class="toolbar">
      <nav class="resp-tabs">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          type="button"
          class="resp-tab"
          :class="{ active: activeTab === tab.key }"
          @click="activeTab = tab.key"
        >
          {{ tab.label }}
          <span v-if="tab.key === 'certs' && certs.length > 0" class="badge">{{ certs.length }}</span>
        </button>
      </nav>
      <div class="toolbar-actions">
        <div v-if="activeTab === 'body'" class="view-modes">
          <button
            v-for="mode in bodyModes"
            :key="mode.key"
            type="button"
            class="mode-btn"
            :class="{ active: bodyViewMode === mode.key }"
            @click="bodyViewMode = mode.key"
          >
            {{ mode.label }}
          </button>
        </div>
        <label v-if="showPrettyToggle" class="toggle">
          <input v-model="prettyJson" type="checkbox" />
          JSON 格式化
        </label>
        <span v-if="charCount && editorTabs.includes(activeTab)" class="size-hint">
          {{ charCount.toLocaleString() }} 字符
        </span>
        <button
          v-if="editorTabs.includes(activeTab)"
          type="button"
          class="btn-copy"
          :disabled="!editorContent"
          @click="copyCurrent"
        >
          {{ copyHint || '复制' }}
        </button>
      </div>
    </div>

    <section class="resp-body">
      <div v-if="editorTabs.includes(activeTab)" class="editor-wrap">
        <MonacoYamlEditor
          v-if="editorContent"
          :key="activeTab"
          :model-value="editorContent"
          :language="editorLanguage"
          :word-wrap="editorWordWrap"
          :readonly="true"
          :reset-scroll-key="activeTab"
          :min-height="320"
        />
        <div v-else class="empty">（空）</div>
      </div>

      <template v-else>
        <div class="cert-scroll">
        <div v-if="certs.length === 0" class="empty">无证书（目标未使用 TLS）</div>
        <div v-else class="cert-list">
          <article
            v-for="(c, i) in certs"
            :key="`${c.serialNumber}-${i}`"
            class="cert"
          >
            <h4>
              证书 #{{ i + 1 }}
              <span v-if="c.valid" class="cert-valid">有效</span>
              <span v-else class="cert-invalid">已过期</span>
            </h4>
            <div class="cert-row"><b>Subject</b><span>{{ formatCertName(c.subject, c.subjectDN) }}</span></div>
            <div class="cert-row"><b>Issuer</b><span>{{ formatCertName(c.issuer, c.issuerDN) }}</span></div>
            <div class="cert-row"><b>有效期</b><span>{{ c.notBefore }} ~ {{ c.notAfter }}</span></div>
            <div class="cert-row"><b>序列号</b><span>{{ c.serialNumber }}</span></div>
            <div class="cert-row"><b>版本</b><span>v{{ c.version }}</span></div>
            <div class="cert-row"><b>签名算法</b><span>{{ c.signatureAlgorithm }}</span></div>
            <div class="cert-row"><b>公钥算法</b><span>{{ c.publicKeyAlgorithm }}</span></div>
            <div v-if="c.publicKey" class="cert-row"><b>公钥指纹</b><span class="mono">{{ c.publicKey }}</span></div>
            <div v-if="c.dnsNames?.length" class="cert-row"><b>DNS</b><span>{{ c.dnsNames.join(', ') }}</span></div>
            <div v-if="c.ipAddresses?.length" class="cert-row"><b>IP</b><span>{{ c.ipAddresses.join(', ') }}</span></div>
            <div v-if="c.emailAddresses?.length" class="cert-row"><b>Email</b><span>{{ c.emailAddresses.join(', ') }}</span></div>
            <div v-if="c.ocspServer?.length" class="cert-row"><b>OCSP</b><span>{{ c.ocspServer.join(', ') }}</span></div>
          </article>
        </div>
        </div>
      </template>
    </section>
  </div>
</template>

<style scoped>
.response-view {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 320px;
  background: var(--color-surface);
}
.meta {
  padding: 10px 14px;
  border-bottom: 1px solid var(--color-border-light);
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  background: linear-gradient(180deg, var(--color-surface-muted) 0%, var(--color-surface) 100%);
}
.status {
  display: flex;
  align-items: center;
  gap: 8px;
}
.status-code {
  font-size: 18px;
  font-weight: 700;
  padding: 2px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border);
  background: var(--color-surface);
  color: var(--color-text);
}
.status-code.ok {
  background: var(--color-success-bg);
  border-color: var(--color-success-border);
  color: var(--color-success);
}
.status-code.redirect {
  background: var(--color-warning-bg);
  border-color: var(--color-warning-border);
  color: var(--color-status-redirect);
}
.status-code.client {
  background: var(--color-status-client-bg);
  border-color: var(--color-status-client-border);
  color: var(--color-status-client);
}
.status-code.server {
  background: var(--color-error-bg);
  border-color: var(--color-error-border);
  color: var(--color-error);
}
.status-text {
  color: var(--color-text);
  font-size: 13px;
  font-weight: 600;
}
.meta-items {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.chip {
  padding: 3px 9px;
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  color: var(--color-text-secondary);
  font-size: 12px;
}
.chip b {
  color: var(--color-text);
  font-weight: 600;
}
.chip.ctype {
  color: var(--color-primary);
  border-color: var(--color-panel-form-border);
  background: var(--color-panel-form);
  font-family: var(--font-mono);
  font-size: 11px;
}
.title {
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 0 12px;
  border-bottom: 1px solid var(--color-border-light);
  background: var(--color-surface);
}
.resp-tabs {
  display: flex;
  gap: 2px;
  flex: 1;
  min-width: 0;
  overflow-x: auto;
}
.resp-tab {
  background: transparent;
  border: none;
  color: var(--color-text-muted);
  padding: 10px 12px;
  border-bottom: 2px solid transparent;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
  transition: color 0.15s, border-color 0.15s;
}
.resp-tab:hover {
  color: var(--color-text-secondary);
}
.resp-tab.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}
.badge {
  margin-left: 4px;
  background: var(--color-primary-soft);
  color: var(--color-primary);
  border-radius: 10px;
  padding: 0 6px;
  font-size: 11px;
  font-weight: 600;
}
.toolbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}
.view-modes {
  display: flex;
  background: var(--color-bg);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  padding: 1px;
  gap: 1px;
}
.mode-btn {
  padding: 2px 8px;
  border: none;
  background: transparent;
  color: var(--color-text-muted);
  cursor: pointer;
  border-radius: 4px;
  font-size: 11px;
  font-family: var(--font-mono);
  transition: all 0.15s;
}
.mode-btn:hover {
  color: var(--color-text-secondary);
}
.mode-btn.active {
  background: var(--color-surface);
  color: var(--color-primary);
  box-shadow: var(--shadow-sm);
}
.toggle {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--color-text-secondary);
  cursor: pointer;
  user-select: none;
}
.size-hint {
  font-size: 11px;
  color: var(--color-text-muted);
  font-family: var(--font-mono);
}
.btn-copy {
  padding: 4px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border);
  background: var(--color-surface);
  color: var(--color-text-secondary);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-copy:hover:not(:disabled) {
  color: var(--color-primary);
  border-color: var(--color-primary);
  background: var(--color-primary-soft);
}
.btn-copy:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.resp-body {
  flex: 1;
  min-height: 0;
  overflow: hidden;
  padding: 10px 12px 12px;
  background: var(--color-bg);
  display: flex;
  flex-direction: column;
}
.editor-wrap {
  flex: 1;
  min-height: 0;
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.editor-wrap :deep(.monaco-host) {
  flex: 1 1 auto;
  min-height: 320px;
  height: 0;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
}
.cert-scroll {
  flex: 1;
  min-height: 0;
  overflow: auto;
}
.cert-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.cert {
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-md);
  padding: 12px 14px;
  box-shadow: var(--shadow-sm);
}
.cert h4 {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--color-text);
  display: flex;
  align-items: center;
  gap: 8px;
}
.cert-valid {
  font-size: 11px;
  font-weight: 500;
  padding: 1px 6px;
  border-radius: 8px;
  background: var(--color-success-bg);
  color: var(--color-success);
  border: 1px solid var(--color-success-border);
}
.cert-invalid {
  font-size: 11px;
  font-weight: 500;
  padding: 1px 6px;
  border-radius: 8px;
  background: var(--color-error-bg);
  color: var(--color-error);
  border: 1px solid var(--color-error-border);
}
.cert-row .mono {
  font-family: var(--font-mono);
  font-size: 11px;
}
.cert-row {
  display: grid;
  grid-template-columns: 90px 1fr;
  font-size: 12.5px;
  padding: 3px 0;
  gap: 8px;
}
.cert-row b {
  color: var(--color-text-muted);
  font-weight: 500;
}
.cert-row span {
  color: var(--color-text);
  word-break: break-all;
}
.empty {
  color: var(--color-text-muted);
  font-size: 13px;
  text-align: center;
  padding: 32px 16px;
  background: var(--color-surface);
  border: 1px dashed var(--color-border-light);
  border-radius: var(--radius-md);
}
</style>
