import { postJSON, type RequestOptions } from './client'
import type { ValidateYAMLInput, ValidateYAMLOutput } from '@/types/api'

/** 校验 YAML 指纹规则，返回是否合法 + outline + 行号错误列表。 */
export function validateYAML(content: string, options?: RequestOptions) {
  return postJSON<ValidateYAMLInput, ValidateYAMLOutput>('/api/v1/yaml/validate', { content }, options)
}
