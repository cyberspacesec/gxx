<script setup lang="ts">
/**
 * 目标 / TLS / 代理 / 超时配置条。
 *
 * 设计：纯 v-model 受控组件，**不主动读写 Pinia store**。
 * - 父组件如果想让该 bar 与 store 同步，应通过 `v-model` 绑定到一个
 *   `computed<RunTargetConfig>({ get, set })`，其中 `set` 调用
 *   `shared.updateTargetConfig(...)` 即可。
 * - 这样数据流是单向的：store → computed → props.modelValue → form；
 *   form → emit → computed.set → store。
 *
 * 历史 `syncStore` prop 与第三路 store→form deep watch 已移除，
 * 因为父组件可以更简洁地通过 computed 拼接 store，避免互相 watch 死锁。
 */
import { reactive, watch } from 'vue'
import type { RunTargetConfig } from '@/stores/shared'

const props = defineProps<{ modelValue: RunTargetConfig }>()

const emit = defineEmits<{
  'update:modelValue': [RunTargetConfig]
}>()

const form = reactive<RunTargetConfig>({ ...props.modelValue })

let updatingFromProps = false

watch(
  () => props.modelValue,
  (value) => {
    updatingFromProps = true
    Object.assign(form, value)
    queueMicrotask(() => { updatingFromProps = false })
  },
  { deep: true },
)

watch(
  form,
  (value) => {
    if (updatingFromProps) return
    emit('update:modelValue', { ...value })
  },
  { deep: true },
)
</script>

<template>
  <div class="target-config-bar panel">
    <label class="field target-field">
      <span class="label">目标</span>
      <input v-model="form.target" class="field-input" placeholder="https://example.com" />
    </label>
    <label class="check"><input v-model="form.useTls" type="checkbox" /> SSL</label>
    <label class="check"><input v-model="form.verifyTls" type="checkbox" /> 验证证书</label>
    <label class="check"><input v-model="form.followRedirects" type="checkbox" /> 跟随重定向</label>
    <label class="field timeout-field">
      <span class="label">超时</span>
      <input v-model.number="form.timeoutSeconds" type="number" min="1" class="field-input tiny" />
    </label>
    <label class="field proxy-field">
      <span class="label">代理</span>
      <input v-model="form.proxy" class="field-input" placeholder="可选" />
    </label>
  </div>
</template>

<style scoped>
.target-config-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  padding: 10px 14px;
  border-radius: var(--radius-md);
}
.field {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.target-field {
  flex: 1;
  min-width: 200px;
}
.proxy-field {
  flex: 1;
  min-width: 160px;
}
.label {
  color: var(--color-text-secondary);
  white-space: nowrap;
  font-size: 12px;
}
.check {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
  color: var(--color-text-secondary);
  font-size: 12px;
}
.field-input.tiny {
  width: 56px;
}
</style>
