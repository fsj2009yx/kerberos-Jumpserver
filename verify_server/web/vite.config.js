import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiTarget = 'http://127.0.0.1:9885'
const apiProxy = {
  '/api': {
    target: apiTarget,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5185,
    proxy: apiProxy,
  },
  preview: {
    port: 4185,
    proxy: apiProxy,
  },
})
