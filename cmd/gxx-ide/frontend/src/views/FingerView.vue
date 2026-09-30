<script setup lang="ts">
/**
 * 指纹编辑视图（IDE 的核心工作台）。
 *
 * 三栏布局（可拖拽中分）：
 * 1. **表单编辑器** —— FingerFormEditor 提供可视化字段。
 * 2. **YAML 预览** —— 由表单实时生成（debounced），只读。
 * 3. **结果面板** —— 规则结果 / 变量 / CEL 调试 tab。
 *
 * 关键能力：
 * - `MonacoYamlEditor` / `PacketDetailDialog` 通过 {@link defineAsyncComponent} 懒加载。
 * - YAML 校验请求支持 `AbortController`，新一次 keystroke 来时 abort 上一次未完成校验。
 * - 运行指纹也支持 AbortController：连点「运行」按钮时丢弃旧结果。
 * - 目标 / TLS / 代理 / 超时直接绑定到 Pinia store，与 RequestView 共享配置。
 */
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { evaluateCEL, isCanceledError, runFingerprint, validateYAML } from '@/api'
import { defaultLibraryDir, listLibrary, loadYAML, saveYAML } from '@/api/library'
import {
  buildSavePath,
  defaultFingerForm,
  formToYaml,
  yamlToForm,
  type FingerFormModel,
} from '@/composables/fingerForm'
import { useHorizontalSplit } from '@/composables/useHorizontalSplit'
import type { EvaluateCELOutput, FingerFileMeta, RuleRun, RunFingerprintOutput, ValidateYAMLOutput } from '@/types/api'
import FingerFormEditor from '@/components/FingerFormEditor.vue'
import TargetConfigBar from '@/components/TargetConfigBar.vue'
import { VAR_TEMPLATES } from '@/composables/fingerHints'
import { useSharedStore, type RunTargetConfig } from '@/stores/shared'

const MonacoYamlEditor = defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))
const PacketDetailDialog = defineAsyncComponent(() => import('@/components/PacketDetailDialog.vue'))

const shared = useSharedStore()
const form = ref<FingerFormModel>(defaultFingerForm())
const libraryRoot = ref('')
const currentPath = ref('')
const generatedYaml = ref(formToYaml(form.value))

const validation = ref<ValidateYAMLOutput | null>(null)

/** 目标 / TLS / 代理 / 超时绑定 store；TargetConfigBar 通过 v-model 双向同步。 */
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

const runLoading = ref(false)
const runResult = ref<RunFingerprintOutput | null>(null)
const runError = ref('')
const saveMessage = ref('')
const openDialog = ref(false)
const libraryFiles = ref<FingerFileMeta[]>([])
const sideTab = ref<'rules' | 'vars' | 'cel'>('rules')

const packetDialog = ref({
  open: false,
  title: '',
  subtitle: '',
  raw: '',
  packetKind: undefined as 'request' | 'response' | undefined,
  fields: [] as { name: string; type: string; desc: string }[],
  celExamples: [] as string[],
})

function openRulePacket(rule: RuleRun, kind: 'request' | 'response') {
  const tpl = VAR_TEMPLATES.find((t) => t.id === kind)
  packetDialog.value = {
    open: true,
    title: `${rule.key} · ${kind === 'request' ? '请求包' : '响应包'}`,
    subtitle: `${rule.method} ${rule.urlEvaluated || rule.path}`,
    raw: kind === 'request' ? rule.requestRaw : rule.responseRaw,
    packetKind: kind,
    fields: tpl?.fields ?? [],
    celExamples: tpl?.celExamples ?? [],
  }
}

function openVarPacket(key: string) {
  const tpl = VAR_TEMPLATES.find((t) => t.id === key)
  if (!tpl || !runResult.value) return
  const ruleWithData = [...runResult.value.rules].reverse().find((r) =>
    key === 'request' ? r.requestRaw : r.responseRaw,
  )
  packetDialog.value = {
    open: true,
    title: tpl.title,
    subtitle: ruleWithData ? `来自 rule ${ruleWithData.key}` : tpl.summary,
    raw: (key === 'request' ? ruleWithData?.requestRaw : ruleWithData?.responseRaw) ?? tpl.sampleRaw ?? '',
    packetKind: key === 'request' || key === 'response' ? key : undefined,
    fields: tpl.fields,
    celExamples: tpl.celExamples ?? [],
  }
}

function closePacketDialog() {
  packetDialog.value.open = false
}

const celForm = reactive({
  expression: 'response.status == 200',
  variablesJSON: `{
  "response": { "status": 200, "body": "" }
}`,
})
const celResult = ref<EvaluateCELOutput | null>(null)
const celError = ref('')

const workspaceRef = ref<HTMLElement | null>(null)
const FORM_MIN_WIDTH = 420
const YAML_MIN_WIDTH = 320
const RESULT_PANEL_WIDTH = 260

const { leftWidth, dragging, onResizeStart } = useHorizontalSplit(workspaceRef, {
  storageKey: 'gxx-ide-finger-form-width',
  defaultWidth: 560,
  minWidth: FORM_MIN_WIDTH,
  reservedRight: RESULT_PANEL_WIDTH + 12,
  minFlexWidth: YAML_MIN_WIDTH,
})

let validateTimer: ReturnType<typeof setTimeout> | null = null
let validateController: AbortController | null = null

watch(
  form,
  () => {
    generatedYaml.value = formToYaml(form.value)
  },
  { deep: true, immediate: true },
)

watch(generatedYaml, () => {
  if (validateTimer) clearTimeout(validateTimer)
  validateController?.abort()
  validateTimer = setTimeout(async () => {
    const controller = new AbortController()
    validateController = controller
    try {
      const out = await validateYAML(generatedYaml.value, { signal: controller.signal })
      if (validateController === controller) {
        validation.value = out
      }
    } catch (err) {
      if (isCanceledError(err) || validateController !== controller) return
      validation.value = {
        valid: false,
        errors: [{ line: 0, column: 0, message: (err as Error).message }],
        outline: null,
      }
    }
  }, 400)
})

let runController: AbortController | null = null

onMounted(async () => {
  libraryRoot.value = (await defaultLibraryDir()).path
})

function onNew() {
  form.value = defaultFingerForm()
  currentPath.value = ''
  runResult.value = null
  runError.value = ''
  saveMessage.value = ''
}

async function onOpenDialog() {
  openDialog.value = true
  libraryFiles.value = await listLibrary(libraryRoot.value, true)
}

async function openFile(file: FingerFileMeta) {
  const loaded = await loadYAML(file.path)
  form.value = yamlToForm(loaded.content)
  currentPath.value = loaded.path
  openDialog.value = false
  saveMessage.value = ''
}

async function onSave() {
  saveMessage.value = ''
  const path = currentPath.value || buildSavePath(libraryRoot.value, form.value.id)
  try {
    await saveYAML(path, generatedYaml.value)
    currentPath.value = path
    saveMessage.value = `已保存到 ${path}`
  } catch (err) {
    saveMessage.value = (err as Error).message
  }
}

async function onRun() {
  runController?.abort()
  const controller = new AbortController()
  runController = controller
  runError.value = ''
  runLoading.value = true
  try {
    const result = await runFingerprint(
      { yaml: generatedYaml.value, ...targetConfig.value },
      { signal: controller.signal },
    )
    if (runController === controller) runResult.value = result
  } catch (err) {
    if (isCanceledError(err) || runController !== controller) return
    runError.value = (err as Error).message
  } finally {
    if (runController === controller) runLoading.value = false
  }
}

onBeforeUnmount(() => {
  if (validateTimer) clearTimeout(validateTimer)
  validateController?.abort()
  runController?.abort()
})

async function onRunCEL() {
  celError.value = ''
  let vars: Record<string, unknown> = {}
  try {
    vars = celForm.variablesJSON.trim() ? JSON.parse(celForm.variablesJSON) : {}
  } catch (err) {
    celError.value = '变量 JSON 解析失败: ' + String(err)
    return
  }
  try {
    celResult.value = await evaluateCEL({ expression: celForm.expression, variables: vars })
  } catch (err) {
    celError.value = (err as Error).message
  }
}

const validationBanner = computed(() => {
  if (!validation.value) return null
  if (validation.value.valid) {
    const o = validation.value.outline
    return {
      level: 'ok' as const,
      text: `校验通过 · ID="${o?.id || ''}" · ${o?.rules?.length ?? 0} 条 rule`,
    }
  }
  const err = validation.value.errors[0]
  return { level: 'err' as const, text: err ? `第 ${err.line} 行：${err.message}` : '解析失败' }
})
</script>

<template>
  <div class="finger-view">
    <div class="top-bar panel">
      <div class="top-bar-main">
        <div class="actions">
          <button type="button" class="btn btn-primary" @click="onNew">新建</button>
          <button type="button" class="btn" @click="onOpenDialog">打开</button>
          <button type="button" class="btn btn-primary" @click="onSave">保存</button>
        </div>
        <div class="validation" :class="validationBanner?.level">
          {{ validationBanner?.text ?? '校验中…' }}
        </div>
        <div class="spacer" />
        <button class="btn btn-primary btn-run" :disabled="runLoading" @click="onRun">
          {{ runLoading ? '运行中…' : '运行指纹' }}
        </button>
      </div>
      <div class="target-row">
        <TargetConfigBar v-model="targetConfig" />
      </div>
    </div>

    <div v-if="saveMessage" class="save-msg panel">{{ saveMessage }}</div>

    <div ref="workspaceRef" class="workspace" :class="{ 'is-resizing': dragging }">
      <section class="form-panel panel" :style="{ width: `${leftWidth}px` }">
        <div class="panel-title panel-header-form">
          <span class="panel-badge form">表单</span>
          规则编辑器
        </div>
        <FingerFormEditor v-model="form" />
      </section>

      <div
        class="split-gutter"
        :class="{ 'is-dragging': dragging }"
        title="拖动调整宽度"
        @mousedown.prevent="onResizeStart"
      />

      <section class="yaml-panel panel">
        <div class="panel-title panel-header-yaml">
          <span class="panel-badge yaml">YAML</span>
          预览（自动生成）
        </div>
        <div class="editor-body">
          <MonacoYamlEditor v-model="generatedYaml" language="yaml" :min-height="420" :readonly="true" />
        </div>
      </section>

      <aside class="result-panel panel">
        <nav class="side-tabs panel-header-result">
          <button :class="{ active: sideTab === 'rules' }" @click="sideTab = 'rules'">规则结果</button>
          <button :class="{ active: sideTab === 'vars' }" @click="sideTab = 'vars'">变量面板</button>
          <button :class="{ active: sideTab === 'cel' }" @click="sideTab = 'cel'">CEL 调试</button>
        </nav>

        <section v-if="sideTab === 'rules'" class="side-content">
          <div v-if="!runResult" class="empty">运行指纹后查看各 rule 的中间结果</div>
          <template v-else>
            <div class="overall" :class="{ ok: runResult.finalResult }">
              <div>最终表达式：<code>{{ runResult.finalExpression }}</code></div>
              <div>
                结果：<b>{{ runResult.finalResult ? '命中' : '未命中' }}</b>
                <span v-if="runResult.expressionError" class="err-text">{{ runResult.expressionError }}</span>
              </div>
            </div>
            <article v-for="r in runResult.rules" :key="r.key" class="rule-card" :class="{ ok: r.result }">
              <header>
                <strong>{{ r.key }}</strong>
                <span class="pill" :class="{ ok: r.result }">{{ r.result ? '命中' : '未命中' }}</span>
                <span v-if="r.statusCode" class="tag">{{ r.statusCode }}</span>
              </header>
              <div class="expr"><code>{{ r.expression }}</code></div>
              <div v-if="r.requestRaw || r.responseRaw" class="packet-actions">
                <button v-if="r.requestRaw" type="button" class="btn btn-small" @click="openRulePacket(r, 'request')">
                  查看请求包
                </button>
                <button v-if="r.responseRaw" type="button" class="btn btn-small" @click="openRulePacket(r, 'response')">
                  查看响应包
                </button>
              </div>
              <div v-if="r.httpError" class="err-text">HTTP：{{ r.httpError }}</div>
              <div v-if="r.celError" class="err-text">CEL：{{ r.celError }}</div>
            </article>
          </template>
        </section>

        <section v-else-if="sideTab === 'vars'" class="side-content">
          <div v-if="!runResult" class="empty">运行指纹后查看 varMap</div>
          <table v-else class="var-table">
            <thead><tr><th>变量</th><th>类型</th><th>值</th></tr></thead>
            <tbody>
              <tr
                v-for="v in runResult.variables"
                :key="v.key"
                :class="{ clickable: v.key === 'request' || v.key === 'response' }"
                @click="(v.key === 'request' || v.key === 'response') && openVarPacket(v.key)"
              >
                <td>
                  {{ v.key }}
                  <span v-if="v.key === 'request' || v.key === 'response'" class="view-link">查看包</span>
                </td>
                <td class="muted">{{ v.type }}</td>
                <td>{{ v.value }}</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section v-else class="side-content cel-panel">
          <label>CEL 表达式</label>
          <textarea v-model="celForm.expression" class="field-input textarea" rows="2"></textarea>
          <label>变量 JSON</label>
          <textarea v-model="celForm.variablesJSON" class="field-input textarea" rows="5"></textarea>
          <button class="btn btn-primary" @click="onRunCEL">运行表达式</button>
          <div v-if="celError" class="err-text">{{ celError }}</div>
          <div v-if="celResult && !celError" class="cel-result">
            <div>类型：<code>{{ celResult.type }}</code></div>
            <pre>{{ celResult.result }}</pre>
          </div>
        </section>
      </aside>
    </div>

    <div v-if="runError" class="run-error panel">{{ runError }}</div>

    <Teleport to="body">
      <Transition name="dialog-fade">
        <div v-if="openDialog" class="open-dialog-mask" role="presentation" @click.self="openDialog = false">
          <div class="dialog-panel panel" role="dialog" aria-modal="true" aria-label="打开指纹文件">
            <header>
              <strong>打开指纹文件</strong>
              <span class="muted">{{ libraryRoot }}</span>
              <button type="button" class="btn btn-small" @click="openDialog = false">关闭</button>
            </header>
            <ul class="file-list">
              <li
                v-for="f in libraryFiles"
                :key="f.path"
                class="file-item"
                tabindex="0"
                @click="openFile(f)"
                @keydown.enter="openFile(f)"
                @keydown.space.prevent="openFile(f)"
              >
                <div class="name">{{ f.outline?.name || f.name }}</div>
                <div class="sub">{{ f.relPath }}</div>
              </li>
            </ul>
          </div>
        </div>
      </Transition>
    </Teleport>

    <PacketDetailDialog
      :open="packetDialog.open"
      :title="packetDialog.title"
      :subtitle="packetDialog.subtitle"
      :raw="packetDialog.raw"
      :packet-kind="packetDialog.packetKind"
      :fields="packetDialog.fields"
      :cel-examples="packetDialog.celExamples"
      @close="closePacketDialog"
    />
  </div>
</template>

<style scoped>
.finger-view {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 16px 16px;
  height: 100%;
  overflow: hidden;
}
.top-bar {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.top-bar-main {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
}
.target-row {
  border-top: 1px solid var(--color-border-light);
}
.target-row :deep(.target-config-bar) {
  border: none;
  box-shadow: none;
  border-radius: 0;
  padding: 8px 16px;
  gap: 12px;
}
.actions {
  display: flex;
  gap: 6px;
}
.btn-run {
  padding: 6px 20px;
  font-weight: 600;
}
.validation {
  padding: 4px 10px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  background: var(--color-bg);
  border: 1px solid var(--color-border-light);
  color: var(--color-text-secondary);
}
.validation.ok {
  background: var(--color-success-bg);
  color: var(--color-success);
  border-color: var(--color-success-border);
}
.validation.err {
  background: var(--color-error-bg);
  color: var(--color-error);
  border-color: var(--color-error-border);
}
.spacer {
  flex: 1;
}
.save-msg {
  padding: 6px 12px;
  font-size: 12px;
  color: var(--color-text-secondary);
}
.workspace {
  display: flex;
  flex: 1;
  min-height: 0;
  align-items: stretch;
  gap: 0;
}
.workspace.is-resizing {
  cursor: col-resize;
  user-select: none;
}
.form-panel {
  flex-shrink: 0;
  min-width: 420px;
  max-width: calc(100% - 420px - 260px);
}
.yaml-panel {
  flex: 1;
  min-width: 320px;
}
.result-panel {
  width: 260px;
  flex-shrink: 0;
  margin-left: 10px;
}
.form-panel,
.yaml-panel,
.result-panel {
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}
.panel-badge {
  display: inline-block;
  padding: 1px 6px;
  margin-right: 8px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.02em;
}
.panel-badge.form {
  background: var(--color-panel-form);
  color: var(--color-primary-active);
  border: 1px solid var(--color-panel-form-border);
}
.panel-badge.yaml {
  background: var(--color-panel-yaml);
  color: var(--color-success);
  border: 1px solid var(--color-panel-yaml-border);
}
.panel-badge.result {
  background: var(--color-panel-result);
  color: #7c3aed;
  border: 1px solid var(--color-panel-result-border);
}
.side-tabs {
  display: flex;
  border-bottom: 1px solid var(--color-border-light);
  background: linear-gradient(180deg, var(--color-surface-muted) 0%, var(--color-surface) 100%);
}
.side-tabs.panel-header-result {
  background: linear-gradient(180deg, var(--color-panel-result) 0%, var(--color-surface) 100%);
  border-bottom-color: var(--color-panel-result-border);
}
.side-tabs button {
  flex: 1;
  padding: 8px 4px;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-size: 12px;
  border-bottom: 2px solid transparent;
}
.side-tabs button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}
.side-content {
  padding: 10px 12px;
  overflow: auto;
  flex: 1;
}
.empty {
  color: var(--color-text-muted);
  font-size: 12px;
  text-align: center;
  padding: 24px 12px;
}
.overall {
  background: var(--color-bg);
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  margin-bottom: 10px;
  border: 1px solid var(--color-border-light);
}
.overall.ok {
  background: var(--color-success-bg);
  border-color: var(--color-success-border);
}
.overall code,
.expr code {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--color-primary);
}
.rule-card {
  background: var(--color-bg);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  padding: 8px 10px;
  margin-bottom: 8px;
  font-size: 12px;
}
.rule-card.ok {
  border-color: var(--color-success-border);
}
.rule-card header {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.pill {
  padding: 0 6px;
  border-radius: 10px;
  font-size: 11px;
  background: var(--color-error-bg);
  color: var(--color-error);
}
.pill.ok {
  background: var(--color-success-bg);
  color: var(--color-success);
}
.tag {
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  padding: 0 6px;
  border-radius: 8px;
  font-size: 11px;
}
.expr {
  margin-top: 4px;
  color: var(--color-text-secondary);
}
.packet-actions {
  display: flex;
  gap: 6px;
  margin-top: 6px;
  flex-wrap: wrap;
}
.var-table tr.clickable {
  cursor: pointer;
}
.var-table tr.clickable:hover {
  background: var(--color-primary-soft);
}
.view-link {
  margin-left: 6px;
  font-size: 10px;
  color: var(--color-primary);
}
.err-text {
  color: var(--color-error);
  font-size: 12px;
  margin-top: 4px;
}
.var-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.var-table th,
.var-table td {
  padding: 4px 6px;
  border-bottom: 1px solid var(--color-border-light);
  text-align: left;
}
.muted {
  color: var(--color-text-muted);
}
.cel-panel label {
  display: block;
  margin: 8px 0 4px;
  font-size: 12px;
  color: var(--color-text-secondary);
}
.textarea {
  font-family: var(--font-mono);
  font-size: 12px;
  resize: vertical;
}
.cel-result {
  margin-top: 10px;
  padding: 8px;
  background: var(--color-success-bg);
  border: 1px solid var(--color-success-border);
  border-radius: var(--radius-sm);
  font-size: 12px;
}
.run-error {
  padding: 8px 12px;
  color: var(--color-error);
  background: var(--color-error-bg);
  border-color: var(--color-error-border);
  font-size: 12px;
}
/* 与 PacketDetailDialog 一致的轻量蒙层：避免 native <dialog> 默认黑色 ::backdrop。 */
.open-dialog-mask {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.18);
  backdrop-filter: blur(2px);
  -webkit-backdrop-filter: blur(2px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 16px;
}
.dialog-panel {
  width: 520px;
  max-height: 70vh;
  display: flex;
  flex-direction: column;
  box-shadow:
    0 24px 48px rgba(15, 23, 42, 0.18),
    0 4px 12px rgba(15, 23, 42, 0.08);
}
.dialog-panel header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--color-border-light);
  background: linear-gradient(180deg, var(--color-surface-muted) 0%, var(--color-surface) 100%);
}
.dialog-panel header strong {
  flex: 1;
}
.file-list {
  list-style: none;
  margin: 0;
  padding: 8px;
  overflow: auto;
}
.file-item {
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  border: 1px solid transparent;
  outline: none;
}
.file-item:hover,
.file-item:focus-visible {
  background: var(--color-primary-soft);
  border-color: var(--color-panel-form-border);
}
.dialog-fade-enter-active,
.dialog-fade-leave-active {
  transition: opacity 0.15s ease-out;
}
.dialog-fade-enter-from,
.dialog-fade-leave-to {
  opacity: 0;
}
.file-list .name {
  font-size: 13px;
  color: var(--color-text);
}
.file-list .sub {
  font-size: 11px;
  color: var(--color-text-muted);
}
.btn-small {
  padding: 2px 10px;
  font-size: 12px;
}
</style>
