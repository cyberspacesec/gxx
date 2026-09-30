import { ref, watch } from 'vue'

const STORAGE_KEY = 'gxx-ide-theme'

function getSystemPreference(): boolean {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
}

function getSavedTheme(): boolean | null {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'dark') return true
  if (saved === 'light') return false
  return null
}

export const isDark = ref(getSavedTheme() ?? getSystemPreference())

function applyTheme(dark: boolean) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light')
  localStorage.setItem(STORAGE_KEY, dark ? 'dark' : 'light')
}

applyTheme(isDark.value)

watch(isDark, (v) => applyTheme(v))

export function toggleTheme() {
  isDark.value = !isDark.value
}
