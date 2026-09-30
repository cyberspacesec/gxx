import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/request' },
  {
    path: '/request',
    name: 'request',
    component: () => import('@/views/RequestView.vue'),
    meta: { title: '请求测试', description: '发送 HTTP 请求 / Raw 报文，查看完整响应' },
  },
  {
    path: '/finger',
    name: 'finger',
    component: () => import('@/views/FingerView.vue'),
    meta: { title: '指纹编辑', description: '编写、校验、运行 YAML 指纹规则' },
  },
  {
    path: '/library',
    name: 'library',
    component: () => import('@/views/LibraryView.vue'),
    meta: { title: '指纹库', description: '管理本地 fingerYaml/ 目录下的指纹' },
  },
]

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
})
