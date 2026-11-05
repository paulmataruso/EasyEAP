import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'node:path'

// Two entry points:
//  - index.html  : the production EasyEAP console (real API data only)
//  - design.html : design-concept prototypes + comparison page (synthetic sample data)
// `vite build` (mode "production") only emits the console; sample data never ships.
export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': resolve(__dirname, 'src') } },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: { '/api': { target: process.env.EASYEAP_API ?? 'http://localhost:8000', changeOrigin: false } },
  },
  build: {
    outDir: mode === 'design' ? 'dist-design' : 'dist',
    rollupOptions: {
      input: (mode === 'design'
        ? { design: resolve(__dirname, 'design.html') }
        : { index: resolve(__dirname, 'index.html'), enroll: resolve(__dirname, 'enroll.html') }) as Record<string, string>,
    },
  },
  test: { environment: 'jsdom', globals: true, setupFiles: ['./src/test-setup.ts'] },
}))
