<script setup lang="ts">
import { onBeforeUnmount, reactive, watch } from 'vue'
import type { FingerFormModel, MatchPart, MatchType, RuleFormItem } from '@/composables/fingerForm'
import {
  MATCH_PART_LABELS,
  MATCH_TYPE_LABELS,
  buildFinalExpression,
  compileMatchers,
  defaultMatcher,
  defaultRule,
  nextRuleKey,
  type FinalLogic,
} from '@/composables/fingerForm'
import CollapsiblePanel from '@/components/CollapsiblePanel.vue'
import { CEL_SNIPPETS, SET_VAR_PRESETS, VAR_TEMPLATES, VAR_USAGE_TIP, type VarTemplate } from '@/composables/fingerHints'
import HintChipList from '@/components/HintChipList.vue'
import PacketDetailDialog from '@/components/PacketDetailDialog.vue'
import { evaluateCEL, isCanceledError } from '@/api'

const form = defineModel<FingerFormModel>({ required: true })

const templateDialog = reactive<{ open: boolean; tpl: VarTemplate | null }>({ open: false, tpl: null })

const sectionOpen = reactive({
  basic: true,
  meta: false,
  set: true,
  templates: false,
  payloads: false,
  rules: true,
})

/**
 * 规则展开/折叠状态。
 *
 * 键为 `rule.key`（而非数组下标）。这样删除中间规则后，
 * 其它规则的折叠状态不会因索引位移被误覆盖。
 */
const ruleOpen = reactive<Record<string, boolean>>({})

function setRuleOpen(key: string, value: boolean) {
  ruleOpen[key] = value
}

/** 默认展开规则；首次访问且未显式设置时返回 true。 */
function isRuleOpen(key: string): boolean {
  return ruleOpen[key] ?? true
}

/**
 * 为可变数组项分配稳定的虚拟 uid，用作 v-for 的 :key。
 *
 * 通过 WeakMap 关联每个对象 → 唯一字符串，对象首次被访问时分配；
 * 这样删除中间项后，相邻项的 key 不会跟随索引偏移，
 * 避免 Vue 复用错误 DOM 导致输入框光标 / 选区错位。
 */
let uidCounter = 0
const itemUid = new WeakMap<object, string>()
function uidFor(obj: object): string {
  let u = itemUid.get(obj)
  if (!u) {
    u = `u${++uidCounter}`
    itemUid.set(obj, u)
  }
  return u
}

function ruleSummary(rule: RuleFormItem): string {
  const req =
    rule.requestType === 'http'
      ? `${rule.method} ${rule.path || '/'}`
      : `${rule.requestType.toUpperCase()} ${rule.host || rule.data.slice(0, 20)}`
  const match =
    rule.expressionMode === 'advanced'
      ? rule.expression
      : `${rule.matcherLogic.toUpperCase()} · ${previewExpression(rule)}`
  return `${req} · ${match}`
}

function openTemplate(tpl: VarTemplate) {
  templateDialog.open = true
  templateDialog.tpl = tpl
}

function closeTemplate() {
  templateDialog.open = false
}

function addSetVar() {
  form.value.setVars.push({ key: '', value: '' })
}

function applySetPreset(preset: { key: string; value: string }) {
  const existing = form.value.setVars.find((v) => v.key === preset.key)
  if (existing) {
    existing.value = preset.value
    return
  }
  form.value.setVars.push({ key: preset.key, value: preset.value })
}

function insertPathVar(rule: RuleFormItem, varName: string) {
  const token = `{{${varName}}}`
  if (rule.path.includes(token)) return
  rule.path = rule.path ? `${rule.path}${token}` : token
}

function appendCelSnippet(rule: RuleFormItem, snippet: string) {
  if (rule.expressionMode === 'advanced') {
    rule.expression = rule.expression ? `${rule.expression} && ${snippet}` : snippet
  } else {
    rule.expressionMode = 'advanced'
    rule.expression = snippet
  }
}

function removeSetVar(index: number) {
  form.value.setVars.splice(index, 1)
}

function togglePayloads(enabled: boolean) {
  form.value.payloads.enabled = enabled
  if (enabled && form.value.payloads.groups.length === 0) {
    form.value.payloads.groups.push({ key: 'set1', vars: [{ key: 'path', value: '/admin' }] })
  }
}

function addPayloadGroup() {
  form.value.payloads.groups.push({
    key: `set${form.value.payloads.groups.length + 1}`,
    vars: [{ key: 'path', value: '/' }],
  })
}

function addPayloadVar(groupIndex: number) {
  form.value.payloads.groups[groupIndex].vars.push({ key: '', value: '' })
}

function addRule() {
  const key = nextRuleKey(form.value.rules)
  form.value.rules.push(defaultRule(key))
  ruleOpen[key] = true
  syncFinalExpression()
}

function removeRule(index: number) {
  const removed = form.value.rules[index]
  form.value.rules.splice(index, 1)
  if (removed?.key) delete ruleOpen[removed.key]
  if (form.value.rules.length === 0) addRule()
  syncFinalExpression()
}

function addMatcher(rule: RuleFormItem) {
  rule.matchers.push(defaultMatcher())
}

function removeMatcher(rule: RuleFormItem, index: number) {
  rule.matchers.splice(index, 1)
  if (rule.matchers.length === 0) rule.matchers.push(defaultMatcher())
}

function addHeader(rule: RuleFormItem) {
  rule.headers.push({ key: '', value: '' })
}

function syncFinalExpression() {
  if (form.value.finalLogic === 'custom') return
  form.value.expression = buildFinalExpression(form.value.rules, form.value.finalLogic)
}

function onFinalLogicChange(logic: FinalLogic) {
  form.value.finalLogic = logic
  syncFinalExpression()
}

function onRuleKeyChange() {
  syncFinalExpression()
}

function onPartChange(matcher: { part: MatchPart; type: MatchType }) {
  if (matcher.part === 'status') matcher.type = 'status_eq'
  else if (matcher.type === 'status_eq') matcher.type = 'contains'
}

function previewExpression(rule: RuleFormItem): string {
  return rule.expressionMode === 'advanced' ? rule.expression : compileMatchers(rule.matchers, rule.matcherLogic)
}

interface CelLintResult { valid: boolean; error: string }
const celLintResults = reactive<Record<string, CelLintResult | null>>({})
const lintTimers: Record<string, ReturnType<typeof setTimeout>> = {}
const lintControllers: Record<string, AbortController> = {}

const dummyVars = {
  response: { status: 200, body: '', headers: {}, raw_header: '', icon_hash: '', latency: 0, raw: '' },
  request: { method: 'GET', url: { scheme: 'https', host: 'example.com', domain: 'example.com', path: '/', query: '', fragment: '' }, headers: {}, body: '', raw: '', raw_header: '', content_type: '' },
}

function lintExpression(key: string, expr: string) {
  if (lintTimers[key]) clearTimeout(lintTimers[key])
  lintControllers[key]?.abort()
  const trimmed = expr.trim()
  if (!trimmed) { celLintResults[key] = null; return }
  lintTimers[key] = setTimeout(async () => {
    const controller = new AbortController()
    lintControllers[key] = controller
    try {
      await evaluateCEL({ expression: trimmed, variables: dummyVars })
      if (lintControllers[key] === controller) celLintResults[key] = { valid: true, error: '' }
    } catch (err) {
      if (isCanceledError(err) || lintControllers[key] !== controller) return
      celLintResults[key] = { valid: false, error: (err as Error).message }
    }
  }, 600)
}

watch(
  () => form.value.rules.map(r => ({ key: r.key, expr: r.expression, mode: r.expressionMode })),
  (rules) => {
    for (const r of rules) {
      if (r.mode === 'advanced' && r.expr.trim()) lintExpression(r.key, r.expr)
      else celLintResults[r.key] = null
    }
  },
  { deep: true },
)

onBeforeUnmount(() => {
  for (const key of Object.keys(lintTimers)) clearTimeout(lintTimers[key])
  for (const key of Object.keys(lintControllers)) lintControllers[key]?.abort()
})
</script>

<template>
  <div class="finger-form">
    <CollapsiblePanel v-model:open="sectionOpen.basic" title="基本信息">
      <label class="field">
        <span>规则 ID</span>
        <input v-model="form.id" class="field-input" />
      </label>
      <label class="field">
        <span>规则组合逻辑</span>
        <div class="logic-row">
          <button
            type="button"
            class="logic-btn"
            :class="{ active: form.finalLogic === 'and' }"
            @click="onFinalLogicChange('and')"
          >
            全部满足 (AND)
          </button>
          <button
            type="button"
            class="logic-btn"
            :class="{ active: form.finalLogic === 'or' }"
            @click="onFinalLogicChange('or')"
          >
            任一满足 (OR)
          </button>
          <button
            type="button"
            class="logic-btn"
            :class="{ active: form.finalLogic === 'custom' }"
            @click="onFinalLogicChange('custom')"
          >
            自定义
          </button>
        </div>
      </label>
      <label class="field">
        <span>总表达式</span>
        <input
          v-model="form.expression"
          class="field-input mono-input"
          placeholder="r0() && r1()"
          :readonly="form.finalLogic !== 'custom'"
        />
        <span v-if="form.finalLogic !== 'custom'" class="field-hint">根据上方组合逻辑自动生成</span>
      </label>
    </CollapsiblePanel>

    <CollapsiblePanel v-model:open="sectionOpen.meta" title="元数据信息">
      <label class="field"><span>名称</span><input v-model="form.info.name" class="field-input" /></label>
      <label class="field"><span>作者</span><input v-model="form.info.author" class="field-input" /></label>
      <label class="field check-field">
        <span>是否验证</span><input v-model="form.info.verified" type="checkbox" />
      </label>
      <label class="field">
        <span>描述</span><textarea v-model="form.info.description" class="field-input textarea" rows="2"></textarea>
      </label>
      <label class="field">
        <span>参考链接</span>
        <textarea v-model="form.info.reference" class="field-input textarea" rows="2" placeholder="每行一个"></textarea>
      </label>
      <label class="field"><span>标签</span><input v-model="form.info.tags" class="field-input" /></label>
      <div class="field-row">
        <label class="field"><span>创建日期</span><input v-model="form.info.created" class="field-input" /></label>
        <label class="field">
          <span>严重级别</span>
          <select v-model="form.info.severity" class="field-input">
            <option value="info">info</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
      </div>
    </CollapsiblePanel>

    <CollapsiblePanel v-model:open="sectionOpen.set" title="全局变量 set">
      <div class="tip-box">{{ VAR_USAGE_TIP }}</div>
      <HintChipList
        title="点击快速添加常用变量："
        :items="SET_VAR_PRESETS.map((p) => ({ label: p.key, value: p.key, desc: `${p.desc} → ${p.value}` }))"
        @pick="(key) => applySetPreset(SET_VAR_PRESETS.find((p) => p.key === key) || { key, value: '' })"
      />
      <div v-for="(v, i) in form.setVars" :key="uidFor(v)" class="var-row">
        <label class="field compact">
          <span class="field-label-required">变量名</span>
          <input v-model="v.key" class="field-input" placeholder="num / hostname" list="set-var-keys" />
        </label>
        <label class="field compact grow">
          <span class="field-label-required">CEL 表达式</span>
          <input v-model="v.value" class="field-input" placeholder="randomInt(1,100) 或 request.url.host" />
        </label>
        <button type="button" class="btn btn-small btn-danger" @click="removeSetVar(i)">删</button>
      </div>
      <datalist id="set-var-keys">
        <option v-for="p in SET_VAR_PRESETS" :key="p.key" :value="p.key">{{ p.desc }}</option>
      </datalist>
      <button type="button" class="btn btn-small" @click="addSetVar">+ 添加自定义变量</button>
    </CollapsiblePanel>

    <CollapsiblePanel
      v-model:open="sectionOpen.templates"
      title="变量模板参考"
      subtitle="单击查看 request / response 数据包"
    >
      <div class="template-grid">
        <button
          v-for="tpl in VAR_TEMPLATES"
          :key="tpl.id"
          type="button"
          class="template-card"
          @click="openTemplate(tpl)"
        >
          <span class="tpl-badge" :class="tpl.category">{{ tpl.category }}</span>
          <strong>{{ tpl.title }}</strong>
          <span class="tpl-summary">{{ tpl.summary }}</span>
        </button>
      </div>
    </CollapsiblePanel>

    <CollapsiblePanel v-model:open="sectionOpen.payloads" title="payloads 多组探测">
      <template #actions>
        <label class="check-field compact-check" @click.stop>
          <input :checked="form.payloads.enabled" type="checkbox" @change="togglePayloads(($event.target as HTMLInputElement).checked)" />
          启用
        </label>
      </template>
      <template v-if="form.payloads.enabled">
        <label class="check-field">
          <input v-model="form.payloads.continue" type="checkbox" /> 命中后继续下一组
        </label>
        <div v-for="(g, gi) in form.payloads.groups" :key="uidFor(g)" class="sub-block">
          <div class="inline-row">
            <span class="sub-label">组名</span>
            <input v-model="g.key" class="field-input" placeholder="set1" />
            <button type="button" class="btn btn-small" @click="addPayloadVar(gi)">添加字段</button>
          </div>
          <div v-for="pv in g.vars" :key="uidFor(pv)" class="inline-row">
            <input v-model="pv.key" class="field-input" placeholder="path" />
            <input v-model="pv.value" class="field-input grow" placeholder="/admin/login" />
          </div>
        </div>
        <button type="button" class="btn btn-small" @click="addPayloadGroup">添加 payload 组</button>
      </template>
    </CollapsiblePanel>

    <CollapsiblePanel v-model:open="sectionOpen.rules" title="规则条件">
      <template #actions>
        <button type="button" class="btn btn-small btn-primary" @click="addRule">添加规则</button>
      </template>

      <CollapsiblePanel
        v-for="(rule, ri) in form.rules"
        :key="rule.key"
        :open="isRuleOpen(rule.key)"
        :title="`规则 ${rule.key}`"
        :subtitle="ruleSummary(rule)"
        @update:open="(v) => setRuleOpen(rule.key, v)"
      >
        <template #actions>
          <button
            v-if="form.rules.length > 1"
            type="button"
            class="btn btn-small btn-danger"
            @click.stop="removeRule(ri)"
          >
            删除
          </button>
        </template>
        <div class="field-row">
          <label class="field">
            <span>Key</span>
            <input v-model="rule.key" class="field-input" @change="onRuleKeyChange" />
          </label>
          <label class="field">
            <span>请求类型</span>
            <select v-model="rule.requestType" class="field-input">
              <option value="http">HTTP</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="ssl">SSL</option>
            </select>
          </label>
        </div>

        <template v-if="rule.requestType === 'http'">
          <div class="field-row">
            <label class="field">
              <span>请求方法</span>
              <select v-model="rule.method" class="field-input">
                <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option>
                <option>HEAD</option><option>OPTIONS</option><option>PATCH</option>
              </select>
            </label>
            <label class="field">
              <span class="field-label-required">请求路径</span>
              <input v-model="rule.path" class="field-input" placeholder="/ 或 /{{ '{{num}}' }}.php" />
              <HintChipList
                v-if="form.setVars.length"
                title="插入 set 变量到路径："
                :items="form.setVars.filter((v) => v.key).map((v) => ({ label: v.key, value: v.key, desc: `{{${v.key}}}` }))"
                @pick="(key) => insertPathVar(rule, key)"
              />
            </label>
          </div>
          <label class="field">
            <span>请求体</span>
            <textarea v-model="rule.body" class="field-input textarea mono" rows="2"></textarea>
          </label>
          <div class="section-head">
            <span class="sub-label">请求头</span>
            <button type="button" class="btn btn-small" @click="addHeader(rule)">添加</button>
          </div>
          <div v-for="h in rule.headers" :key="uidFor(h)" class="inline-row">
            <input v-model="h.key" class="field-input" placeholder="User-Agent" />
            <input v-model="h.value" class="field-input grow" placeholder="Mozilla/5.0" />
          </div>
          <label class="check-field"><input v-model="rule.followRedirects" type="checkbox" /> 跟随重定向</label>
        </template>

        <template v-else>
          <label class="field"><span>Host</span><input v-model="rule.host" class="field-input" placeholder="{{ '{{hostname}}' }}:80" /></label>
          <label class="field"><span>Data</span><textarea v-model="rule.data" class="field-input textarea mono" rows="2"></textarea></label>
        </template>

        <div class="section-head">
          <span class="sub-label">匹配器</span>
          <select v-model="rule.expressionMode" class="field-input mode-select">
            <option value="matchers">可视化匹配</option>
            <option value="advanced">高级 CEL 表达式</option>
          </select>
        </div>

        <template v-if="rule.expressionMode === 'matchers'">
          <div class="logic-toolbar">
            <span class="sub-label">匹配器组合</span>
            <div class="logic-row compact">
              <button
                type="button"
                class="logic-btn"
                :class="{ active: rule.matcherLogic === 'and' }"
                @click="rule.matcherLogic = 'and'"
              >
                AND
              </button>
              <button
                type="button"
                class="logic-btn"
                :class="{ active: rule.matcherLogic === 'or' }"
                @click="rule.matcherLogic = 'or'"
              >
                OR
              </button>
            </div>
          </div>
          <div v-for="(matcher, mi) in rule.matchers" :key="uidFor(matcher)" class="matcher-block">
            <div class="matcher-head">
              <strong>匹配器 {{ mi + 1 }}</strong>
              <button type="button" class="btn btn-small btn-danger" @click="removeMatcher(rule, mi)">删</button>
            </div>
            <div class="field-row">
              <label class="field">
                <span>匹配部分</span>
                <select v-model="matcher.part" class="field-input" @change="onPartChange(matcher)">
                  <option v-for="(label, key) in MATCH_PART_LABELS" :key="key" :value="key">{{ label }}</option>
                </select>
              </label>
              <label v-if="matcher.part !== 'status'" class="field">
                <span>匹配类型</span>
                <select v-model="matcher.type" class="field-input">
                  <option v-for="(label, key) in MATCH_TYPE_LABELS" :key="key" :value="key">{{ label }}</option>
                </select>
              </label>
            </div>
            <label v-if="matcher.part === 'header'" class="field">
              <span>响应头名称</span>
              <input v-model="matcher.headerName" class="field-input" placeholder="server" />
            </label>
            <label class="field">
              <span>{{ matcher.part === 'status' ? '状态码' : '匹配内容' }}</span>
              <input v-model="matcher.value" class="field-input" :placeholder="matcher.part === 'status' ? '200' : '关键字或正则'" />
            </label>
          </div>
          <button type="button" class="btn btn-small" @click="addMatcher(rule)">添加匹配器</button>
          <div class="preview-expr">生成表达式：<code>{{ previewExpression(rule) }}</code></div>
        </template>

        <template v-else>
          <label class="field">
            <span>CEL 表达式</span>
            <textarea v-model="rule.expression" class="field-input textarea mono" rows="3"></textarea>
            <div v-if="celLintResults[rule.key]" class="cel-lint" :class="{ ok: celLintResults[rule.key]?.valid, err: !celLintResults[rule.key]?.valid }">
              {{ celLintResults[rule.key]?.valid ? '✓ 语法正确' : `✗ ${celLintResults[rule.key]?.error}` }}
            </div>
            <HintChipList
              title="插入常用表达式片段："
              :items="CEL_SNIPPETS.map((s) => ({ label: s.label, value: s.value, desc: s.value }))"
              @pick="(v) => appendCelSnippet(rule, v)"
            />
          </label>
        </template>
      </CollapsiblePanel>
    </CollapsiblePanel>
  </div>

  <PacketDetailDialog
    :open="templateDialog.open"
    :title="templateDialog.tpl?.title ?? ''"
    :subtitle="templateDialog.tpl?.summary"
    :raw="templateDialog.tpl?.sampleRaw"
    :fields="templateDialog.tpl?.fields"
    :cel-examples="templateDialog.tpl?.celExamples"
    @close="closeTemplate"
  />
</template>

<style scoped>
.finger-form { overflow: auto; height: 100%; padding: 14px 16px; }
.field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px; }
.field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.field span, .sub-label { font-size: 12px; color: var(--color-text-secondary); font-weight: 500; }
.field-hint { font-size: 11px; color: var(--color-text-muted); margin-top: 2px; }
.mono-input { font-family: var(--font-mono); font-size: 12px; }
.check-field { flex-direction: row; align-items: center; gap: 6px; font-size: 12px; color: var(--color-text-secondary); }
.compact-check { margin: 0; font-size: 11px; }
.hint { font-size: 11px; color: var(--color-text-muted); margin: 0 0 8px; }
.textarea { resize: vertical; min-height: 48px; }
.textarea.mono, .preview-expr code { font-family: var(--font-mono); font-size: 11px; }
.inline-row { display: flex; gap: 6px; margin-bottom: 6px; align-items: center; }
.inline-row .grow { flex: 1; }
.var-row { display: flex; gap: 8px; align-items: flex-end; margin-bottom: 8px; }
.field.compact { margin-bottom: 0; flex: 1; min-width: 0; }
.field.compact.grow { flex: 2; }
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
.matcher-block, .sub-block {
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  padding: 10px;
  margin-bottom: 8px;
  background: var(--color-surface-muted);
}
.logic-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
  padding: 6px 8px;
  background: var(--color-surface-muted);
  border-radius: var(--radius-sm);
}
.matcher-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.matcher-head strong { font-size: 12px; }
.btn-small { padding: 3px 10px; font-size: 12px; }
.mode-select { max-width: 160px; }
.preview-expr { margin-top: 8px; padding: 8px 10px; background: var(--color-panel-form); border-radius: var(--radius-sm); font-size: 11px; color: var(--color-text-secondary); word-break: break-all; border: 1px solid var(--color-panel-form-border); }
.preview-expr code { color: var(--color-primary); }
.template-grid { display: grid; grid-template-columns: 1fr; gap: 8px; }
.template-card {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  padding: 10px 12px;
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-sm);
  background: var(--color-surface-muted);
  cursor: pointer;
  text-align: left;
  transition: all 0.15s;
}
.template-card:hover {
  border-color: var(--color-primary);
  background: var(--color-primary-soft);
}
.template-card strong { font-size: 12px; color: var(--color-text); }
.tpl-summary { font-size: 11px; color: var(--color-text-muted); line-height: 1.4; }
.tpl-badge {
  padding: 1px 6px;
  border-radius: 8px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
}
.tpl-badge.request { background: var(--color-panel-form); color: var(--color-primary-active); }
.tpl-badge.response { background: var(--color-panel-yaml); color: var(--color-success); }
.tpl-badge.set { background: var(--color-warning-bg); color: var(--color-status-redirect); }
.cel-lint { padding: 4px 8px; margin-top: 4px; border-radius: var(--radius-sm); font-size: 11px; font-family: var(--font-mono); word-break: break-all; }
.cel-lint.ok { color: var(--color-success); background: var(--color-success-bg); }
.cel-lint.err { color: var(--color-error); background: var(--color-error-bg); }
.finger-form :deep(.collapse-panel .collapse-panel) {
  border-color: var(--color-border-light);
  box-shadow: none;
}
.finger-form :deep(.collapse-panel .collapse-panel .collapse-header) {
  background: var(--color-surface);
  padding: 8px 10px;
}
</style>
