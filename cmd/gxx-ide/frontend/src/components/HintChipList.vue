<script setup lang="ts">
defineProps<{
  title?: string
  items: { label: string; value: string; desc?: string }[]
}>()

const emit = defineEmits<{
  pick: [value: string]
}>()
</script>

<template>
  <div v-if="items.length" class="hint-block">
    <div v-if="title" class="hint-title">{{ title }}</div>
    <div class="chips">
      <button
        v-for="item in items"
        :key="item.label + item.value"
        type="button"
        class="chip"
        :title="item.desc || item.value"
        @click="emit('pick', item.value)"
      >
        {{ item.label }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.hint-block {
  margin: 6px 0 10px;
}
.hint-title {
  font-size: 11px;
  color: var(--color-text-muted);
  margin-bottom: 6px;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  padding: 2px 8px;
  border-radius: 12px;
  border: 1px solid var(--color-border-light);
  background: var(--color-surface);
  color: var(--color-primary);
  font-size: 11px;
  cursor: pointer;
  transition: all 0.15s;
}
.chip:hover {
  background: var(--color-primary-soft);
  border-color: var(--color-primary);
}
</style>
