<script setup lang="ts">
defineProps<{
  title: string
  subtitle?: string
}>()

const open = defineModel<boolean>('open', { default: true })
</script>

<template>
  <section class="collapse-panel" :class="{ 'is-open': open }">
    <div class="collapse-header">
      <span class="title-wrap">
        <strong>{{ title }}</strong>
        <span v-if="subtitle" class="subtitle">{{ subtitle }}</span>
      </span>
      <span class="header-extra" @click.stop><slot name="actions" /></span>
      <button type="button" class="btn-collapse" @click="open = !open">
        {{ open ? '折叠 ▴' : '展开 ▾' }}
      </button>
    </div>
    <div v-show="open" class="collapse-body">
      <slot />
    </div>
  </section>
</template>

<style scoped>
.collapse-panel {
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background: var(--color-surface);
  margin-bottom: 10px;
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.collapse-header {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 10px 12px;
  background: var(--color-surface-muted);
}
.title-wrap {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.title-wrap strong {
  font-size: 13px;
  color: var(--color-text);
}
.subtitle {
  font-size: 11px;
  color: var(--color-text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.header-extra {
  flex-shrink: 0;
}
.btn-collapse {
  flex-shrink: 0;
  background: transparent;
  border: none;
  color: var(--color-text-muted);
  font-size: 14px;
  cursor: pointer;
  padding: 2px 6px;
  transition: color 0.15s;
}
.btn-collapse:hover {
  color: var(--color-primary);
}
.collapse-body {
  padding: 12px;
  border-top: 1px solid var(--color-border-light);
}
</style>
