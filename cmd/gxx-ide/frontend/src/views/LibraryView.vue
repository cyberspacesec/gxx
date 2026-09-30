<script setup lang="ts">
/**
 * 指纹库视图（CRUD 单个 .yml 文件）。
 *
 * - 左侧文件列表显示 outline / 大小，点击进入编辑；
 * - 右侧 Monaco 编辑器（懒加载）展示 YAML 内容；
 * - 「新建」面板内联在 header 下方，避免额外弹窗。
 */
import { computed, defineAsyncComponent, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import {
  defaultLibraryDir, deleteYAML, isCanceledError, listLibrary, loadYAML, saveYAML,
} from '@/api'
import type { FingerFileMeta } from '@/types/api'

const MonacoYamlEditor = defineAsyncComponent(() => import('@/components/MonacoYamlEditor.vue'))

interface TreeNode {
  name: string
  path: string
  isDir: boolean
  children: TreeNode[]
  file?: FingerFileMeta
}

function buildTree(fileList: FingerFileMeta[]): TreeNode[] {
  const root: TreeNode[] = []
  const dirMap = new Map<string, TreeNode>()

  function ensureDir(parts: string[]): TreeNode {
    const p = parts.join('/')
    if (dirMap.has(p)) return dirMap.get(p)!
    const node: TreeNode = { name: parts[parts.length - 1], path: p, isDir: true, children: [] }
    dirMap.set(p, node)
    if (parts.length === 1) {
      root.push(node)
    } else {
      const parent = ensureDir(parts.slice(0, -1))
      if (!parent.children.some(c => c.path === p)) parent.children.push(node)
    }
    return node
  }

  for (const file of fileList) {
    const parts = file.relPath.replace(/\\/g, '/').split('/')
    const leaf: TreeNode = { name: file.name, path: file.relPath, isDir: false, children: [], file }
    if (parts.length === 1) {
      root.push(leaf)
    } else {
      ensureDir(parts.slice(0, -1)).children.push(leaf)
    }
  }

  function sortNodes(nodes: TreeNode[]) {
    nodes.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
      return a.name.localeCompare(b.name)
    })
    for (const n of nodes) if (n.children.length) sortNodes(n.children)
  }
  sortNodes(root)
  return root
}

interface FlatTreeItem { node: TreeNode; depth: number }

const dirExpanded = reactive<Record<string, boolean>>({})

function isDirExpanded(path: string): boolean {
  return dirExpanded[path] ?? true
}

function toggleDir(path: string) {
  dirExpanded[path] = !isDirExpanded(path)
}

const rootDir = ref('')
const includeOutline = ref(true)
const files = ref<FingerFileMeta[]>([])
const loading = ref(false)
const errorMessage = ref('')

const selectedPath = ref('')
const editingContent = ref('')
const editorBusy = ref(false)
const saving = ref(false)

const newFileName = ref('')
const createPanelOpen = ref(false)

/** 让外部 `confirm()` 在 Wails WebView 中存在性弱化，统一封装。 */
function confirmDelete(path: string): boolean {
  return window.confirm(`确定删除 ${path} ?`)
}

let refreshController: AbortController | null = null
let openController: AbortController | null = null

onMounted(async () => {
 try { rootDir.value = (await defaultLibraryDir()).path; await refresh() }
 catch (err) { errorMessage.value = (err as Error).message }
})

async function refresh() {
  refreshController?.abort()
  const controller = new AbortController()
  refreshController = controller
  errorMessage.value = ''
  loading.value = true
  try {
    const result = await listLibrary(rootDir.value, includeOutline.value, { signal: controller.signal })
    if (refreshController === controller) files.value = result
  } catch (err) {
    if (isCanceledError(err) || refreshController !== controller) return
    errorMessage.value = (err as Error).message
  } finally {
    if (refreshController === controller) loading.value = false
  }
}

async function openFile(file: FingerFileMeta) {
 if (saving.value) return
  openController?.abort()
  const controller = new AbortController()
  openController = controller
  editorBusy.value = true
  try {
    const loaded = await loadYAML(file.path, { signal: controller.signal })
    if (openController !== controller) return
    editingContent.value = loaded.content
    selectedPath.value = loaded.path
  } catch (err) {
    if (isCanceledError(err) || openController !== controller) return
    errorMessage.value = (err as Error).message
  } finally {
    if (openController === controller) editorBusy.value = false
  }
}

async function save() {
  if (!selectedPath.value || editorBusy.value) return
  saving.value = true
  editorBusy.value = true
  try {
    await saveYAML(selectedPath.value, editingContent.value)
    await refresh()
  } catch (err) {
    errorMessage.value = (err as Error).message
  } finally {
    editorBusy.value = false
    saving.value = false
  }
}

async function remove() {
  if (!selectedPath.value || editorBusy.value || !confirmDelete(selectedPath.value)) return
  const deletingPath = selectedPath.value
  editorBusy.value = true
  try {
    await deleteYAML(deletingPath)
    if (selectedPath.value === deletingPath) { selectedPath.value = ''; editingContent.value = '' }
    await refresh()
  } catch (err) {
    errorMessage.value = (err as Error).message
  } finally { editorBusy.value = false }
}

function toggleCreatePanel() {
  createPanelOpen.value = !createPanelOpen.value
  if (!createPanelOpen.value) newFileName.value = ''
}

async function createNew() {
  const name = newFileName.value.trim()
  if (!name) return
  const normalizedName = /\.(ya?ml)$/i.test(name) ? name : `${name}.yml`
  const path = `${rootDir.value.replace(/[/\\]+$/, '')}/${normalizedName}`
  const createdDate = new Date().toISOString().slice(0, 10).split('-').join('/')
  const template = `id: ${normalizedName.replace(/\.[^.]+$/, '')}\n\ninfo:\n  name: \n  author: \n  created: ${createdDate}\n\nrules:\n  r0:\n    request:\n      method: GET\n      path: /\n    expression: response.status == 200\n\nexpression: r0()\n`
  try {
    await saveYAML(path, template)
    newFileName.value = ''
    createPanelOpen.value = false
    await refresh()
    const createdFile = files.value.find((f) => f.path === path)
    if (createdFile) await openFile(createdFile)
  } catch (err) {
    errorMessage.value = (err as Error).message
  }
}

const canCreate = computed(() => newFileName.value.trim().length > 0)

const fileTree = computed(() => buildTree(files.value))

const flatTree = computed<FlatTreeItem[]>(() => {
  const result: FlatTreeItem[] = []
  function walk(nodes: TreeNode[], depth: number) {
    for (const node of nodes) {
      result.push({ node, depth })
      if (node.isDir && isDirExpanded(node.path)) walk(node.children, depth + 1)
    }
  }
  walk(fileTree.value, 0)
  return result
})

onBeforeUnmount(() => {
  refreshController?.abort()
  openController?.abort()
})
</script>

<template>
  <div class="library-view">
    <aside class="file-pane">
      <header>
        <input v-model="rootDir" class="input" placeholder="指纹根目录" />
        <button type="button" class="btn" @click="refresh">刷新</button>
        <button type="button" class="btn btn-primary" @click="toggleCreatePanel">新建</button>
      </header>
      <div v-if="createPanelOpen" class="create-panel">
        <input
          v-model="newFileName"
          class="input"
          placeholder="文件名，如 my-finger.yml"
          @keyup.enter="createNew"
        />
        <button type="button" class="btn btn-primary" :disabled="!canCreate" @click="createNew">创建</button>
        <button type="button" class="btn" @click="toggleCreatePanel">取消</button>
      </div>
      <label class="opt"><input v-model="includeOutline" type="checkbox" @change="refresh" /> 解析 outline</label>
      <div v-if="loading" class="loading">扫描中…</div>
      <div v-else-if="errorMessage" class="err">{{ errorMessage }}</div>
      <div v-else-if="files.length === 0" class="empty">该目录下没有 .yaml / .yml 文件</div>
      <div v-else class="tree-scroll">
        <div
          v-for="item in flatTree"
          :key="item.node.path"
          class="tree-item"
          :class="{
            'is-dir': item.node.isDir,
            active: !item.node.isDir && item.node.file?.path === selectedPath,
            broken: !item.node.isDir && !!item.node.file?.parseError,
          }"
          :style="{ paddingLeft: `${12 + item.depth * 18}px` }"
          tabindex="0"
          @click="item.node.isDir ? toggleDir(item.node.path) : openFile(item.node.file!)"
          @keydown.enter="item.node.isDir ? toggleDir(item.node.path) : openFile(item.node.file!)"
          @keydown.space.prevent="item.node.isDir ? toggleDir(item.node.path) : openFile(item.node.file!)"
        >
          <span class="tree-icon" :class="{ 'file-icon': !item.node.isDir }">
            {{ item.node.isDir ? (isDirExpanded(item.node.path) ? '▾' : '▸') : '•' }}
          </span>
          <div class="tree-content">
            <div class="name">
              {{ item.node.isDir ? item.node.name : (item.node.file?.outline?.name || item.node.name) }}
            </div>
            <template v-if="!item.node.isDir && item.node.file">
              <div class="sub">{{ (item.node.file.sizeBytes / 1024).toFixed(1) }} KB</div>
              <div v-if="item.node.file.outline" class="meta">
                <span class="tag">{{ item.node.file.outline.ruleKeys?.length ?? 0 }} 条 rule</span>
                <span v-if="item.node.file.outline.tags" class="tag">{{ item.node.file.outline.tags }}</span>
              </div>
              <div v-if="item.node.file.parseError" class="parse-err">{{ item.node.file.parseError }}</div>
            </template>
          </div>
        </div>
      </div>
    </aside>
    <section class="edit-pane">
      <header>
        <div class="path">{{ selectedPath || '从左侧选择文件或点击「新建」' }}</div>
        <div class="actions">
          <button type="button" class="btn" :disabled="!selectedPath || editorBusy" @click="save">保存</button>
          <button type="button" class="btn btn-danger" :disabled="!selectedPath" @click="remove">删除</button>
        </div>
      </header>
      <MonacoYamlEditor v-if="selectedPath" v-model="editingContent" language="yaml" :min-height="500" />
      <div v-else class="placeholder">没有打开的文件。</div>
    </section>
  </div>
</template>

<style scoped>
.library-view {
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 10px;
  padding: 12px 16px 16px;
  height: 100%;
  overflow: hidden;
}
.file-pane,
.edit-pane {
  background: var(--color-surface);
  border: 1px solid var(--color-border-light);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-sm);
  overflow: hidden;
}
.file-pane {
  display: flex;
  flex-direction: column;
}
.file-pane header {
  display: flex;
  gap: 6px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--color-border-light);
}
.create-panel {
  display: flex;
  gap: 6px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--color-border-light);
  background: var(--color-surface-muted);
}
.input {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-sm);
  color: var(--color-text);
  padding: 5px 8px;
  font-size: 12px;
  outline: none;
  flex: 1;
}
.input:focus {
  border-color: var(--color-primary);
}
.btn {
  padding: 5px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--color-border);
  background: var(--color-surface);
  color: var(--color-text-secondary);
  cursor: pointer;
  font-size: 12px;
  white-space: nowrap;
}
.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.btn-primary {
  background: var(--color-primary);
  color: #fff;
  border-color: var(--color-primary);
}
.btn-danger {
  color: var(--color-error);
  border-color: var(--color-error-border);
}
.opt {
  padding: 8px 12px;
  font-size: 12px;
  color: var(--color-text-muted);
  display: flex;
  gap: 6px;
  align-items: center;
}
.loading,
.empty,
.err {
  padding: 14px;
  color: var(--color-text-muted);
  font-size: 13px;
  text-align: center;
}
.err,
.parse-err {
  color: var(--color-error);
}
.tree-scroll {
  flex: 1;
  overflow: auto;
  padding: 4px 0 12px;
}
.tree-item {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 6px 10px;
  cursor: pointer;
  border: 1px solid transparent;
  margin: 1px 6px;
  border-radius: var(--radius-sm);
  outline: none;
}
.tree-item:hover,
.tree-item:focus-visible {
  background: var(--color-bg);
}
.tree-item:focus-visible {
  border-color: var(--color-primary);
}
.tree-item.active {
  background: var(--color-primary-soft);
  border-color: var(--color-panel-form-border);
}
.tree-item.broken {
  border-color: var(--color-error-border);
}
.tree-item.is-dir .name {
  font-weight: 500;
  color: var(--color-text-secondary);
}
.tree-icon {
  flex-shrink: 0;
  width: 16px;
  font-size: 12px;
  line-height: 20px;
  text-align: center;
  color: var(--color-text-muted);
}
.file-icon {
  font-size: 10px;
  color: var(--color-primary);
}
.tree-content {
  flex: 1;
  min-width: 0;
}
.tree-content .name {
  color: var(--color-text);
  font-size: 13px;
  font-weight: 500;
}
.tree-content .sub {
  color: var(--color-text-muted);
  font-size: 11px;
  margin-top: 2px;
}
.tree-content .meta {
  display: flex;
  gap: 6px;
  margin-top: 4px;
  flex-wrap: wrap;
}
.tag {
  background: var(--color-bg);
  color: var(--color-text-secondary);
  padding: 1px 6px;
  border-radius: 8px;
  font-size: 11px;
  border: 1px solid var(--color-border-light);
}
.parse-err {
  font-size: 11px;
  margin-top: 4px;
}
.edit-pane {
  display: flex;
  flex-direction: column;
}
.edit-pane header {
  display: flex;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--color-border-light);
  align-items: center;
}
.path {
  flex: 1;
  color: var(--color-text-secondary);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.actions {
  display: flex;
  gap: 6px;
}
.placeholder {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-text-muted);
}
</style>
