import { getJSON, postJSON, deleteJSON, type RequestOptions } from './client'
import type { FingerFileMeta } from '@/types/api'

/** 默认指纹库目录路径（与主项目 fingerYaml/ 对齐）。 */
export function defaultLibraryDir(options?: RequestOptions) {
  return getJSON<{ path: string }>('/api/v1/library/default', undefined, options)
}

/** 列出指纹库下所有 .yaml/.yml 文件元信息（可选 outline）。 */
export function listLibrary(rootDir: string, includeOutline = true, options?: RequestOptions) {
  return getJSON<FingerFileMeta[]>('/api/v1/library/list', { rootDir, includeOutline }, options)
}

/** 加载单个指纹文件内容。 */
export function loadYAML(path: string, options?: RequestOptions) {
  return getJSON<{ path: string; content: string }>('/api/v1/library/load', { path }, options)
}

/** 保存指纹文件内容（后端会先校验 YAML 合法性）。 */
export function saveYAML(path: string, content: string, options?: RequestOptions) {
  return postJSON<{ path: string; content: string }, { path: string }>(
    '/api/v1/library/save',
    { path, content },
    options,
  )
}

/** 删除指纹文件（后端会校验路径在指纹库下）。 */
export function deleteYAML(path: string, options?: RequestOptions) {
  return deleteJSON<{ path: string }>('/api/v1/library/delete', { path }, options)
}
