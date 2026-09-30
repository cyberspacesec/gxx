import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

// Wails v2 默认把前端构建产物输出到 frontend/dist，并由 Go 端 //go:embed all:frontend/dist 嵌入。
// 开发模式下通过 Vite 代理把 /api 与 /swagger 转发到本地 Gin server（默认 :9527），
// 让前端开发体验与 production 环境完全一致。
// 端口与 ide-dev.sh 的 GXX_IDE_API_PORT 保持一致。
const apiPort = process.env.GXX_IDE_API_PORT || '9527'
const apiTarget = `http://127.0.0.1:${apiPort}`

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2020',
    rollupOptions: {
      output: {
        manualChunks: {
          monaco: ['monaco-editor/esm/vs/editor/editor.api'],
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/swagger': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/healthz': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
