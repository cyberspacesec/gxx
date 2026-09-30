<script setup lang="ts">
/**
 * 请求测试视图：手动调试单个 HTTP 请求。
 *
 * 支持两种输入模式：
 * - **URL 参数**：method 下拉 + URL + headers（每行 key:value）+ body。
 * - **Raw HTTP**：直接编辑完整 HTTP raw 报文，使用 Monaco `http` 语言高亮。
 *
 * 目标 / SSL / 代理 / 超时 / 跟随重定向 通过 {@link useSharedStore} 与 FingerView 共享，
 * 由 `<TargetConfigBar>` 统一渲染，避免在不同视图重复填写。
 *
 * 并发保护：每次发送前 `abort` 旧请求的 `AbortController`，避免快速连点后
 * 旧响应覆盖新响应造成 UI 与实际请求不一致。
 *
 * 性能：`MonacoYamlEditor` / `ResponseView` 通过 {@link defineAsyncComponent} 懒加载，
 * 让首屏体积大幅缩小（Monaco ~2MB 不在初始 chunk 中）。
 */
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { isCanceledError, sendRequest } from '@/api'
import { useSharedStore, type RunTargetConfig } from '@/stores/shared'
import type { RequestMode, SendRequestInput, SendRequestOutput } from '@/types/api'
import { pickHttpRawLanguage } from '@/composables/httpLanguage'

const configCollapsed = ref(false)
const methodOpen = ref(false)

const httpMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const

const methodColors: Record<string, string> = {
  GET: '#059669',
  POST: '#d97706',
  PUT: '#2563eb',
  PATCH: '#7c3aed',
  DELETE: '#dc2626',
  HEAD: '#64748b',
  OPTIONS: '#0891b2',
}

function selectMethod(m: string) {
  form.method = m
  methodOpen.value = false
}

function handleClickOutside(e: MouseEvent) {
  const target = e.target as HTMLElement
  if (!target.closest('.method-dropdown')) {
    methodOpen.value = false
  }
}


const ResponseView = defineAsyncComponent(() => import('@/components/ResponseView.vue'))
const MonacoYamlEditor = defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))

const shared = useSharedStore()

/** 请求体相关字段（与目标/网络配置解耦；目标配置由 TargetConfigBar 直接对接 store）。 */
interface RequestForm {
  mode: RequestMode
  method: string
  headers: Record<string, string>
  body: string
  raw: string
}

const form = reactive<RequestForm>({
  mode: 'url',
  method: 'GET',
  headers: {},
  body: '',
  raw: '',
})

const customHeadersText = ref('User-Agent: Mozilla/5.0\nAccept: */*')

const loading = ref(false)
const response = ref<SendRequestOutput | null>(null)
const errorMessage = ref('')

/** 目标 / TLS / 代理 / 超时直接绑定到 Pinia store；TargetConfigBar 通过 v-model 读写。 */
const targetConfig = computed<RunTargetConfig>({
  get: () => ({
    target: shared.target,
    proxy: shared.proxy,
    timeoutSeconds: shared.timeoutSeconds,
    useTls: shared.useTls,
    verifyTls: shared.verifyTls,
    followRedirects: shared.followRedirects,
  }),
  set: (v) => shared.updateTargetConfig(v),
})

watch(customHeadersText, (text) => {
  const map: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    const idx = t.indexOf(':')
    if (idx <= 0) continue
    map[t.slice(0, idx).trim()] = t.slice(idx + 1).trim()
  }
  form.headers = map
}, { immediate: true })

/** Raw 模式编辑器语言：完整报文走 `http`，否则降级到 plaintext / body 嗅探。 */
const rawLanguage = computed(() => pickHttpRawLanguage(form.raw))

/** Monaco v-model 输入端兜底，避免 undefined 进编辑器（首次渲染前 form.raw 可能为空）。 */
const rawModel = computed(() => form.raw)

function onRawUpdate(value: string) {
  form.raw = value
}

let abortController: AbortController | null = null

async function onSend() {
  abortController?.abort()
  const controller = new AbortController()
  abortController = controller
  errorMessage.value = ''
  loading.value = true

  const payload: SendRequestInput = {
    ...targetConfig.value,
    mode: form.mode,
    method: form.method,
    headers: form.headers,
    body: form.body,
    raw: form.raw,
  }

  try {
    const result = await sendRequest(payload, { signal: controller.signal })
    if (abortController !== controller) return
    response.value = result
    shared.updateFromResponse({
      target: payload.target,
      lastRequestRaw: result?.requestRaw || '',
      lastResponseRaw: result?.rawHeader || '',
      lastResponseTitle: result?.title || '',
    })
  } catch (err) {
    if (isCanceledError(err) || abortController !== controller) return
    errorMessage.value = (err as Error).message
  } finally {
    if (abortController === controller) loading.value = false
  }
}

const exampleRaw = `GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*

`

/** 填充示例 raw 报文，便于首次使用者快速体验。 */
function pasteExample() { form.raw = exampleRaw }

onMounted(() => document.addEventListener('click', handleClickOutside))

onBeforeUnmount(() => {
  abortController?.abort()
  document.removeEventListener('click', handleClickOutside)
})
</script>

<template>
  <div class="request-view">
    <div class="config">
      <div class="url-row">
        <div v-if="form.mode === 'url'" class="method-dropdown" @click.stop="methodOpen = !methodOpen">
          <button type="button" class="method-trigger" :style="{ color: methodColors[form.method] || '#4f46e5' }">
            {{ form.method }}
          </button>
          <Transition name="dropdown-fade">
            <div v-if="methodOpen" class="method-menu">
              <button
                v-for="m in httpMethods"
                :key="m"
                type="button"
                class="method-option"
                :class="{ active: form.method === m }"
                :style="{ color: methodColors[m] }"
                @click="selectMethod(m)"
              >
                {{ m }}
              </button>
            </div>
          </Transition>
        </div>
        <div v-else class="raw-pill">RAW</div>
        <input
          v-model="shared.target"
          class="url-input"
          placeholder="输入请求地址，例如 https://example.com"
          @keydown.enter="onSend"
        />
        <button type="button" class="send-btn" :disabled="loading" @click="onSend">
          {{ loading ? '请求中…' : '发 送' }}
        </button>
      </div>

      <div class="options-row">
        <div class="options-left">
          <label class="opt-check"><input v-model="shared.useTls" type="checkbox" /><span>SSL</span></label>
          <label class="opt-check"><input v-model="shared.verifyTls" type="checkbox" /><span>验证证书</span></label>
          <label class="opt-check"><input v-model="shared.followRedirects" type="checkbox" /><span>重定向</span></label>
          <label class="opt-inline">
            <span>超时</span>
            <input v-model.number="shared.timeoutSeconds" type="number" min="1" class="opt-num" />
            <span class="opt-unit">s</span>
          </label>
          <label class="opt-inline proxy-opt">
            <span>代理</span>
            <input v-model="shared.proxy" class="opt-text" placeholder="http://..." />
          </label>
        </div>
        <div class="options-right">
          <div class="mode-tabs">
            <button type="button" :class="{ active: form.mode === 'url' }" @click="form.mode = 'url'">URL</button>
            <button type="button" :class="{ active: form.mode === 'raw' }" @click="form.mode = 'raw'">Raw</button>
          </div>
          <button type="button" class="btn-collapse" @click="configCollapsed = !configCollapsed">
            {{ configCollapsed ? '展开 ▾' : '折叠 ▴' }}
          </button>
        </div>
      </div>

      <div v-show="!configCollapsed" class="config-body">
        <template v-if="form.mode === 'url'">
          <div class="form-grid">
            <div class="form-col">
              <label class="sub-label">请求头（每行 Key: Value）</label>
              <textarea v-model="customHeadersText" class="input textarea" rows="3"></textarea>
            </div>
            <div class="form-col">
              <label class="sub-label">请求体</label>
              <textarea
                v-model="form.body"
                class="input textarea"
                rows="3"
                placeholder='{"key":"value"}'
              ></textarea>
            </div>
          </div>
        </template>

        <template v-else>
          <div class="raw-toolbar">
            <button type="button" class="btn btn-ghost" @click="pasteExample">填充示例报文</button>
          </div>
          <div class="raw-editor-host">
            <MonacoYamlEditor
              :model-value="rawModel"
              :language="rawLanguage"
              :min-height="200"
              word-wrap="off"
              @update:model-value="onRawUpdate"
            />
          </div>
        </template>
      </div>

      <div v-if="errorMessage" class="error">{{ errorMessage }}</div>
    </div>

    <div class="response-area">
      <ResponseView v-if="response" :response="response" />
      <div v-else class="empty">点击右上角的「发送请求」获取响应数据。</div>
    </div>
  </div>
</template>

<style scoped>
.request-view {
  display: grid;
  grid-template-rows: auto 1fr;
  gap: 10px;
  height: 100%;
  padding: 12px 16px 16px;
  overflow: hidden;
}
.config {
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
}
.url-row {
  display: flex;
  align-items: center;
  padding: 14px 20px;
  gap: 12px;
}
.method-dropdown {
  position: relative;
  flex-shrink: 0;
}
.method-trigger {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 8px 14px;
  border: 1px solid var(--color-border);
  background: var(--color-surface);
  font-weight: 700;
  font-size: 14px;
  cursor: pointer;
  border-radius: var(--radius-sm);
  min-width: 80px;
  justify-content: center;
  transition: border-color 0.15s;
}
.method-trigger:hover {
  border-color: var(--color-primary);
}
.method-arrow {
  font-size: 10px;
  color: var(--color-text-muted);
}
.method-menu {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  min-width: 120px;
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  box-shadow: 0 8px 24px rgba(15, 23, 42, 0.12);
  z-index: 50;
  padding: 4px;
}
.method-option {
  display: block;
  width: 100%;
  padding: 8px 14px;
  border: none;
  background: transparent;
  font-weight: 700;
  font-size: 13px;
  text-align: left;
  cursor: pointer;
  border-radius: 4px;
  transition: background 0.1s;
}
.method-option:hover {
  background: var(--color-bg);
}
.method-option.active {
  background: var(--color-primary-soft);
}
.dropdown-fade-enter-active,
.dropdown-fade-leave-active {
  transition: opacity 0.12s, transform 0.12s;
}
.dropdown-fade-enter-from,
.dropdown-fade-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
.raw-pill {
  padding: 8px 14px;
  border: 1px solid var(--color-border);
  background: var(--color-surface);
  color: var(--color-primary-active);
  font-weight: 700;
  font-size: 13px;
  border-radius: var(--radius-sm);
  letter-spacing: 0.04em;
}
.url-input {
  flex: 1;
  min-width: 0;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
  font-size: 14px;
  font-family: var(--font-mono);
  color: var(--color-text);
  background: var(--color-surface);
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.url-input::placeholder {
  color: var(--color-text-muted);
}
.url-input:focus {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-soft);
}
.send-btn {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 10px 40px;
  letter-spacing: 0.12em;
  border: none;
  background: var(--color-primary);
  color: #fff;
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;
  border-radius: var(--radius-sm);
  transition: all 0.15s;
  box-shadow: 0 1px 3px rgba(79, 70, 229, 0.3);
}
.send-btn:hover:not(:disabled) {
  background: var(--color-primary-hover);
  box-shadow: 0 2px 8px rgba(79, 70, 229, 0.4);
}
.send-btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.options-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 16px;
  border-top: 1px solid var(--color-border-light);
  flex-wrap: wrap;
}
.options-left {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.options-right {
  display: flex;
  align-items: center;
  gap: 6px;
}
.opt-check {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--color-text-secondary);
  cursor: pointer;
  white-space: nowrap;
}
.opt-inline {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 12px;
  color: var(--color-text-secondary);
  white-space: nowrap;
}
.opt-num {
  width: 46px;
  padding: 3px 6px;
  border: 1px solid var(--color-border);
  border-radius: 4px;
  background: var(--color-surface);
  color: var(--color-text);
  font-size: 12px;
  text-align: center;
  outline: none;
}
.opt-num:focus { border-color: var(--color-primary); }
.opt-unit { color: var(--color-text-muted); font-size: 11px; }
.opt-text {
  width: 110px;
  padding: 3px 6px;
  border: 1px solid var(--color-border);
  border-radius: 4px;
  background: var(--color-surface);
  color: var(--color-text);
  font-size: 12px;
  outline: none;
}
.opt-text:focus { border-color: var(--color-primary); }
.btn-collapse {
  background: transparent;
  border: none;
  color: var(--color-text-muted);
  font-size: 14px;
  cursor: pointer;
  padding: 2px 6px;
  transition: color 0.15s;
}
.btn-collapse:hover { color: var(--color-primary); }
.config-body {
  padding: 12px 16px 14px;
  border-top: 1px solid var(--color-border-light);
}
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}
@media (max-width: 800px) {
  .form-grid { grid-template-columns: 1fr; }
  .options-left { gap: 8px; }
}
.form-col {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.raw-toolbar {
  margin-bottom: 10px;
}
.row { display: flex; gap: 8px; align-items: center; }
.mode-tabs {
  display: flex;
  gap: 0;
}
.mode-tabs button {
  padding: 8px 16px;
  background: transparent;
  color: var(--color-text-muted);
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
  transition: all 0.15s;
}
.mode-tabs button:hover {
  color: var(--color-text-secondary);
}
.mode-tabs button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}
.sub-label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--color-text-secondary);
  margin-bottom: 2px;
}
.input {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  color: var(--color-text);
  padding: 7px 10px;
  font-size: 13px;
  font-family: inherit;
  outline: none;
  transition: border-color 0.15s, box-shadow 0.15s;
}
.input:focus {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-primary-soft);
}
.input.textarea {
  width: 100%;
  resize: vertical;
  min-height: 64px;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.6;
}
.raw-editor-host {
  display: flex;
  flex-direction: column;
  min-height: 200px;
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.raw-editor-host :deep(.monaco-host) {
  flex: 1 1 auto;
  min-height: 200px;
  border: none;
  border-radius: 0;
}
.btn {
  padding: 6px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  cursor: pointer;
  font-size: 13px;
  font-weight: 500;
}
.btn-primary {
  background: var(--color-primary);
  color: #fff;
  border-color: var(--color-primary);
}
.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.btn-ghost {
  background: var(--color-surface);
  color: var(--color-text-secondary);
  border: 1px solid var(--color-border);
}
.error {
  padding: 8px 10px;
  background: var(--color-error-bg);
  color: var(--color-error);
  border: 1px solid var(--color-error-border);
  border-radius: var(--radius-sm);
  font-size: 12px;
}
.response-area {
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-md);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.response-area :deep(.response-view) {
  flex: 1;
}
.empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: var(--color-text-muted);
  font-size: 13px;
}
</style>
