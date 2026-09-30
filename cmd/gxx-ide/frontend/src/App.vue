<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { isDark, toggleTheme } from '@/composables/useTheme'

const route = useRoute()
const router = useRouter()

const tabs = computed(() =>
  router.options.routes
    .filter((r) => r.name)
    .map((r) => ({
      name: r.name as string,
      path: r.path,
      title: (r.meta as Record<string, string>)?.title || r.path,
    })),
)

// Swagger UI 走相对路径：wails 模式由 AssetServer fallback 到 Gin；
// 浏览器开发模式由 vite proxy 转发到 Gin server。
const swaggerURL = '/swagger/index.html'
</script>

<template>
  <div class="app-shell">
    <header class="app-header panel">
      <div class="brand">GXX 指纹规则编辑器</div>
      <nav class="nav-tabs">
        <button
          v-for="tab in tabs"
          :key="tab.name"
          class="nav-tab"
          :class="{ active: route.name === tab.name }"
          @click="router.push(tab.path)"
        >
          {{ tab.title }}
        </button>
      </nav>
      <button class="theme-toggle" :title="isDark ? '切换到亮色' : '切换到暗色'" @click="toggleTheme">
        {{ isDark ? '☀️' : '🌙' }}
      </button>
      <a :href="swaggerURL" target="_blank" rel="noopener" class="swagger-link"> API 文档 </a>
    </header>
    <main class="app-main">
      <router-view />
    </main>
  </div>
</template>

<style scoped>
.app-shell {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
  background: var(--color-bg);
}
.app-header {
  display: flex;
  align-items: center;
  gap: 24px;
  padding: 0 20px;
  height: 52px;
  flex-shrink: 0;
  border-radius: 0;
  border-top: none;
  border-left: none;
  border-right: none;
  background: var(--color-surface);
  border-bottom: 1px solid var(--color-border-light);
  box-shadow: var(--shadow-sm);
}
.brand {
  font-size: 15px;
  font-weight: 700;
  color: var(--color-text);
  white-space: nowrap;
  letter-spacing: -0.01em;
}
.nav-tabs {
  display: flex;
  gap: 4px;
  flex: 1;
}
.nav-tab {
  padding: 6px 16px;
  border: none;
  background: transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  border-radius: var(--radius-sm);
  font-size: 13px;
}
.nav-tab:hover {
  color: var(--color-primary);
  background: var(--color-primary-soft);
}
.nav-tab.active {
  color: var(--color-primary);
  background: var(--color-primary-soft);
  font-weight: 600;
}
.theme-toggle {
  background: transparent;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  padding: 4px 10px;
  cursor: pointer;
  font-size: 14px;
  color: var(--color-text-secondary);
  transition: all 0.15s;
  line-height: 1;
}
.theme-toggle:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
  background: var(--color-primary-soft);
}
.swagger-link {
  color: var(--color-text-muted);
  font-size: 12px;
  text-decoration: none;
  white-space: nowrap;
}
.swagger-link:hover {
  color: var(--color-primary);
}
.app-main {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
</style>
