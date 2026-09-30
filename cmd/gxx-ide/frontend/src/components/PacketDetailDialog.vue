<script setup lang="ts">
/**
 * 请求 / 响应包详情对话框。
 *
 * 三标签页：
 * - **数据包 Raw**：完整 HTTP 报文，使用自定义 `http` 语言整体高亮，
 *   覆盖请求行、状态行、headers、body 分隔等。
 * - **字段说明**：变量字段 schema（用于 CEL 调试参考）。
 * - **CEL 示例**：从 fingerHints 派生的常用表达式片段。
 *
 * 视觉上为模态遮罩：用半透明蓝灰背景 + 轻量模糊代替「死黑」backdrop，
 * 避免在 Wails WebView 中产生硬边阴影。
 */
import { computed, defineAsyncComponent, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { httpBodyWordWrap, pickHttpRawLanguage } from '@/composables/httpLanguage'

const MonacoYamlEditor = defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))

/** 单个字段在 schema 中的描述。 */
export interface FieldDoc {
  name: string
  type: string
  desc: string
}

const props = defineProps<{
  /** 是否显示对话框。 */
  open: boolean
  /** 标题（如 `r0 · 请求包`）。 */
  title: string
  /** 副标题（一般展示 URL / Method 等上下文）。 */
  subtitle?: string
  /** HTTP 报文原文，包含 start-line + headers + body。 */
  raw?: string
  /** 变量字段表（可选）。 */
  fields?: FieldDoc[]
  /** CEL 示例代码片段（可选）。 */
  celExamples?: string[]
  /** 报文类型，仅用于 Monaco key 隔离避免实例复用错配。 */
  packetKind?: 'request' | 'response'
}>()

const emit = defineEmits<{ close: [] }>()

type Tab = 'raw' | 'fields' | 'cel'
const activeTab = ref<Tab>('raw')

watch(
  () => props.open,
  (v) => {
    if (v) activeTab.value = props.raw ? 'raw' : props.fields?.length ? 'fields' : 'cel'
  },
)

const rawText = computed(() => props.raw ?? '')

const rawLanguage = computed(() => pickHttpRawLanguage(rawText.value))

const rawWordWrap = computed(() => httpBodyWordWrap(rawText.value, rawLanguage.value))

/** Esc 关闭：仅在对话框打开时挂载键盘监听，避免污染全局。 */
function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && props.open) {
    e.stopPropagation()
    emit('close')
  }
}

/**
 * 焦点管理：
 * - 打开时记录触发焦点的元素，并把焦点交给「关闭」按钮，让键盘用户可立即 Tab/Esc 操作；
 * - 关闭时恢复焦点到打开前的元素，避免焦点丢到 `<body>`。
 */
const closeBtnRef = ref<HTMLButtonElement | null>(null)
let previousActiveElement: HTMLElement | null = null

watch(
  () => props.open,
  async (v) => {
    if (v) {
      previousActiveElement = (document.activeElement as HTMLElement) ?? null
      window.addEventListener('keydown', onKeydown)
      await nextTick()
      closeBtnRef.value?.focus()
    } else {
      window.removeEventListener('keydown', onKeydown)
      previousActiveElement?.focus?.()
      previousActiveElement = null
    }
  },
  { immediate: true },
)

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog-fade">
      <div v-if="open" class="packet-dialog-mask" role="presentation" @click.self="emit('close')">
        <div
          class="dialog-panel panel"
          role="dialog"
          aria-modal="true"
          :aria-label="title"
        >
          <header>
            <div class="head-text">
              <strong>{{ title }}</strong>
              <span v-if="subtitle" class="muted">{{ subtitle }}</span>
            </div>
            <button ref="closeBtnRef" type="button" class="btn btn-small" @click="emit('close')">关闭</button>
          </header>

          <nav class="dialog-tabs">
            <button
              v-if="raw"
              type="button"
              :class="{ active: activeTab === 'raw' }"
              @click="activeTab = 'raw'"
            >数据包 Raw</button>
            <button
              v-if="fields?.length"
              type="button"
              :class="{ active: activeTab === 'fields' }"
              @click="activeTab = 'fields'"
            >字段说明</button>
            <button
              v-if="celExamples?.length"
              type="button"
              :class="{ active: activeTab === 'cel' }"
              @click="activeTab = 'cel'"
            >CEL 示例</button>
          </nav>

          <section class="dialog-body">
            <div v-if="activeTab === 'raw'" class="raw-editor">
              <MonacoYamlEditor
                v-if="rawText"
                :key="`packet-${packetKind ?? 'generic'}`"
                :model-value="rawText"
                :language="rawLanguage"
                :word-wrap="rawWordWrap"
                :readonly="true"
                :reset-scroll-key="activeTab"
                :min-height="360"
              />
              <div v-else class="empty">（无数据）</div>
            </div>

            <table v-else-if="activeTab === 'fields'" class="field-table">
              <thead>
                <tr>
                  <th>字段</th>
                  <th>类型</th>
                  <th>说明</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="f in fields" :key="f.name">
                  <td><code>{{ f.name }}</code></td>
                  <td class="muted">{{ f.type }}</td>
                  <td>{{ f.desc }}</td>
                </tr>
              </tbody>
            </table>

            <div v-else-if="activeTab === 'cel'" class="cel-list">
              <pre v-for="ex in celExamples" :key="ex" class="cel-block">{{ ex }}</pre>
            </div>
          </section>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
/* 用普通 div 模态层取代原生 <dialog>：在 Wails WebView 中表现更稳定，
   且 backdrop 颜色完全由我们控制（不会受 ::backdrop 默认黑色影响）。 */
.packet-dialog-mask {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 200;
  padding: 16px;
  background: rgba(15, 23, 42, 0.18);
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
}
.dialog-panel {
  width: min(860px, 96vw);
  max-height: 82vh;
  display: flex;
  flex-direction: column;
  min-height: 0;
  box-shadow:
    0 24px 48px rgba(15, 23, 42, 0.18),
    0 4px 12px rgba(15, 23, 42, 0.08);
}
.dialog-panel header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-border-light);
  background: linear-gradient(180deg, var(--color-surface-muted) 0%, var(--color-surface) 100%);
}
.dialog-fade-enter-active,
.dialog-fade-leave-active {
  transition: opacity 0.15s ease-out;
}
.dialog-fade-enter-from,
.dialog-fade-leave-to {
  opacity: 0;
}
.dialog-fade-enter-active .dialog-panel,
.dialog-fade-leave-active .dialog-panel {
  transition: transform 0.18s ease-out;
}
.dialog-fade-enter-from .dialog-panel {
  transform: translateY(8px);
}
.dialog-fade-leave-to .dialog-panel {
  transform: translateY(4px);
}
.head-text {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.head-text strong {
  font-size: 14px;
}
.muted {
  font-size: 11px;
  color: var(--color-text-muted);
}
.dialog-tabs {
  display: flex;
  gap: 4px;
  padding: 8px 12px 0;
  border-bottom: 1px solid var(--color-border-light);
}
.dialog-tabs button {
  padding: 6px 12px;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-size: 12px;
  border-bottom: 2px solid transparent;
}
.dialog-tabs button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}
.dialog-body {
  padding: 12px 16px 16px;
  overflow: hidden;
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.raw-editor {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.raw-editor :deep(.monaco-host) {
  flex: 1 1 auto;
  min-height: 360px;
  height: 0;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
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
.cel-block {
  margin: 0;
  padding: 12px;
  background: var(--color-surface-muted);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-all;
}
.cel-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  overflow: auto;
}
.field-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  overflow: auto;
}
.field-table th,
.field-table td {
  padding: 6px 8px;
  border-bottom: 1px solid var(--color-border-light);
  text-align: left;
  vertical-align: top;
}
.field-table code {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--color-primary);
}
</style>
