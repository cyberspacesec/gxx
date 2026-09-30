import { postJSON, type RequestOptions } from './client'
import type { SendRequestInput, SendRequestOutput } from '@/types/api'

/** 发送 HTTP 请求并返回完整响应（含 raw header / body / TLS 证书）。 */
export function sendRequest(input: SendRequestInput, options?: RequestOptions) {
  return postJSON<SendRequestInput, SendRequestOutput>('/api/v1/request/send', input, options)
}
