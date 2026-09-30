import { postJSON, type RequestOptions } from './client'
import type {
  RunFingerprintInput,
  RunFingerprintOutput,
  EvaluateCELInput,
  EvaluateCELOutput,
} from '@/types/api'

/** 运行指纹规则，逐 rule 返回 request/response/CEL 中间结果与最终命中。 */
export function runFingerprint(input: RunFingerprintInput, options?: RequestOptions) {
  return postJSON<RunFingerprintInput, RunFingerprintOutput>('/api/v1/finger/run', input, options)
}

/** 在给定变量上求值 CEL 表达式（用于 CEL 调试面板）。 */
export function evaluateCEL(input: EvaluateCELInput, options?: RequestOptions) {
  return postJSON<EvaluateCELInput, EvaluateCELOutput>('/api/v1/cel/evaluate', input, options)
}
