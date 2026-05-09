import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const apiTarget = 'http://127.0.0.1:9882'
const apiProxy = {
  '/api': {
    target: apiTarget,
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5182,
    proxy: apiProxy,
  },
  preview: {
    port: 4182,
    proxy: apiProxy,
  },
})
