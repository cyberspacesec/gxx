import { defineStore } from 'pinia'

export interface RunTargetConfig {
  target: string
  proxy: string
  timeoutSeconds: number
  useTls: boolean
  verifyTls: boolean
  followRedirects: boolean
}

interface SharedState extends RunTargetConfig {
  lastRequestRaw: string
  lastResponseRaw: string
  lastResponseTitle: string
}

const defaultTargetConfig = (): RunTargetConfig => ({
  target: 'https://example.com',
  proxy: '',
  timeoutSeconds: 10,
  useTls: true,
  verifyTls: false,
  followRedirects: true,
})

// 跨视图共享：请求测试与指纹运行共用同一套目标 / SSL / 代理配置。
export const useSharedStore = defineStore('shared', {
  state: (): SharedState => ({
    ...defaultTargetConfig(),
    lastRequestRaw: '',
    lastResponseRaw: '',
    lastResponseTitle: '',
  }),
  actions: {
    updateFromResponse(payload: Partial<Pick<SharedState, 'lastRequestRaw' | 'lastResponseRaw' | 'lastResponseTitle' | 'target'>>) {
      Object.assign(this, payload)
    },
    updateTargetConfig(payload: Partial<RunTargetConfig>) {
      Object.assign(this, payload)
    },
  },
})
