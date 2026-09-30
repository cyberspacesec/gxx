<script setup lang="ts">
/**
 * Monaco 编辑器统一封装（YAML / CEL / HTTP / 其它静态语言）。
 *
 * 命名沿用 `MonacoYamlEditor` 是历史遗留：实际承载所有 Monaco 使用场景。
 * 通过 `language` prop 切换语言，HTTP 报文场景会同时切换到自定义主题 `gxx-http`，
 * 让 method/header/status 等 token 拿到独立配色。
 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api'
import { setupMonaco } from '@/composables/monaco'
import { isDark } from '@/composables/useTheme'

/** 支持的编辑器语言。`http` 用于 HTTP 报文高亮（请求 / 响应均适用）。 */
export type SupportedLanguage =
  | 'yaml'
  | 'cel'
  | 'plaintext'
  | 'html'
  | 'json'
  | 'xml'
  | 'http'

const props = withDefaults(
  defineProps<{
    modelValue: string
    language?: SupportedLanguage
    readonly?: boolean
    minHeight?: number
    wordWrap?: 'on' | 'off'
    /** Tab 切换时传入新 key，仅此时滚到顶部 */
    resetScrollKey?: string | number
  }>(),
  {
    language: 'yaml',
    readonly: false,
    minHeight: 240,
    wordWrap: 'on',
    resetScrollKey: undefined,
  },
)

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
}>()

const container = ref<HTMLDivElement | null>(null)
let editor: monaco.editor.IStandaloneCodeEditor | null = null
let resizeObserver: ResizeObserver | null = null

function revealTop() {
  if (!editor) return
  editor.setScrollTop(0)
  editor.setScrollLeft(0)
  editor.revealLineNearTop(1, monaco.editor.ScrollType.Immediate)
}

function createEditor() {
  if (!container.value) return
  editor?.dispose()
  editor = monaco.editor.create(container.value, {
    value: props.modelValue,
    language: props.language ?? 'yaml',
    theme: isDark.value ? 'github-dark' : 'github-light',
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 13,
    lineHeight: 20,
    fontFamily: 'JetBrains Mono, SF Mono, Menlo, Consolas, monospace',
    tabSize: 2,
    insertSpaces: true,
    wordWrap: props.wordWrap,
    scrollBeyondLastLine: true,
    padding: { top: 8, bottom: 12 },
    scrollbar: {
      useShadows: false,
      vertical: 'visible',
      horizontal: 'visible',
      verticalScrollbarSize: 12,
      horizontalScrollbarSize: 12,
    },
    readOnly: props.readonly ?? false,
    smoothScrolling: true,
    bracketPairColorization: { enabled: true },
  })
  editor.onDidChangeModelContent(() => {
    if (!editor) return
    const v = editor.getValue()
    if (v !== props.modelValue) emit('update:modelValue', v)
  })
  requestAnimationFrame(revealTop)
}

onMounted(async () => {
  await setupMonaco()
  createEditor()
  if (container.value && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(() => editor?.layout())
    resizeObserver.observe(container.value)
  }
})

watch(() => props.modelValue, (v) => {
  if (editor && editor.getValue() !== v) {
    editor.setValue(v)
  }
})

watch(() => props.language, (lang) => {
  if (!editor) return
  const model = editor.getModel()
  if (model) monaco.editor.setModelLanguage(model, lang ?? 'yaml')
})

watch(() => props.wordWrap, (wrap) => {
  editor?.updateOptions({ wordWrap: wrap })
})

watch(() => props.resetScrollKey, () => {
  requestAnimationFrame(revealTop)
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  resizeObserver = null
  editor?.dispose()
  editor = null
})
</script>

<template>
  <div
    ref="container"
    class="monaco-host"
    :style="{ minHeight: `${minHeight ?? 240}px` }"
  />
</template>

<style scoped>
.monaco-host {
  flex: 1 1 auto;
  width: 100%;
  min-height: inherit;
  height: 0;
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
</style>
