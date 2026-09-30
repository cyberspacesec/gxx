/**
 * 通用 axios 客户端封装。
 *
 * 设计要点：
 * - **单例 axios**：所有领域模块共享同一个 `apiClient`（共用 interceptor / 默认 timeout）。
 * - **统一响应**：后端 `{code, message, data}` 结构由响应拦截器解构，业务错误抛 {@link APIClientError}。
 * - **相对路径 baseURL**：dev 走 vite proxy，prod 走 Wails AssetServer fallback；无固定端口耦合。
 * - **AbortSignal 支持**：所有 helper 接受 `RequestOptions.signal`，调用方可在新请求到来时
 *   `controller.abort()` 旧请求，避免响应竞态覆盖结果。
 */
import axios, { type AxiosInstance, AxiosError, type AxiosRequestConfig } from 'axios'
import type { APIResponse } from '@/types/api'

const API_BASE = ''

/** 业务请求选项（目前仅 AbortSignal；未来可扩展自定义 timeout / retries）。 */
export interface RequestOptions {
  /** 用于取消请求；新请求开始时 abort 旧的可避免竞态。 */
  signal?: AbortSignal
}

class APIClientError extends Error {
  code: number
  /** 是否由调用方主动取消；调用方可据此忽略错误。 */
  readonly canceled: boolean

  constructor(code: number, message: string, canceled = false) {
    super(message)
    this.code = code
    this.canceled = canceled
    this.name = 'APIClientError'
  }
}

/** 是否为取消错误（用于调用方 `if (err.canceled) return`）。 */
export function isCanceledError(err: unknown): boolean {
  if (err instanceof APIClientError) return err.canceled
  if (axios.isCancel(err)) return true
  if (err instanceof Error && err.name === 'CanceledError') return true
  return false
}

function createClient(): AxiosInstance {
  const instance = axios.create({
    baseURL: API_BASE,
    timeout: 60_000,
    headers: { 'Content-Type': 'application/json' },
  })

  instance.interceptors.request.use(async (config) => {
    const bridge = (window as Window & { go?: { main?: { APISession?: { Token(): Promise<string> } } } }).go?.main?.APISession
    const token = bridge ? await bridge.Token() : import.meta.env.VITE_GXX_IDE_TOKEN
    if (token) config.headers.set('Authorization', `Bearer ${token}`)
    return config
  })

  instance.interceptors.response.use(
    (resp) => {
      const body = resp.data as APIResponse<unknown>
      if (body && typeof body === 'object' && 'code' in body) {
        if (body.code !== 200) {
          throw new APIClientError(body.code, body.message)
        }
      }
      return resp
    },
    (err: AxiosError<APIResponse<unknown>>) => {
      if (axios.isCancel(err)) {
        throw new APIClientError(0, 'request canceled', true)
      }
      if (err.response?.data?.code) {
        throw new APIClientError(err.response.data.code, err.response.data.message || err.message)
      }
      throw new APIClientError(err.response?.status || 0, err.message)
    },
  )
  return instance
}

export const apiClient = createClient()

function withSignal(options?: RequestOptions): AxiosRequestConfig | undefined {
  return options?.signal ? { signal: options.signal } : undefined
}

export async function postJSON<TIn, TOut>(
  path: string,
  payload: TIn,
  options?: RequestOptions,
): Promise<TOut> {
  const resp = await apiClient.post<APIResponse<TOut>>(path, payload, withSignal(options))
  return resp.data.data as TOut
}

export async function getJSON<TOut>(
  path: string,
  params?: Record<string, unknown>,
  options?: RequestOptions,
): Promise<TOut> {
  const resp = await apiClient.get<APIResponse<TOut>>(path, {
    params,
    ...(withSignal(options) ?? {}),
  })
  return resp.data.data as TOut
}

export async function deleteJSON<TOut>(
  path: string,
  params?: Record<string, unknown>,
  options?: RequestOptions,
): Promise<TOut> {
  const resp = await apiClient.delete<APIResponse<TOut>>(path, {
    params,
    ...(withSignal(options) ?? {}),
  })
  return resp.data.data as TOut
}

export { APIClientError, API_BASE }
