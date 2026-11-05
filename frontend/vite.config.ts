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
  resolve: { alias: { '@': resolve(import.meta.dirname, 'src') } },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: { '/api': { target: process.env.EASYEAP_API ?? 'http://localhost:8000', changeOrigin: false } },
  },
  build: {
    outDir: mode === 'design' ? 'dist-design' : 'dist',
    // Never inline fonts as data: URIs: the proxy's Content Security Policy allows fonts only from 'self'.
    assetsInlineLimit: (file: string) => (/\.(woff2?|ttf|otf)$/.test(file) ? false : undefined),
    rollupOptions: {
      input: (mode === 'design'
        ? { design: resolve(import.meta.dirname, 'design.html') }
        : { index: resolve(import.meta.dirname, 'index.html'), enroll: resolve(import.meta.dirname, 'enroll.html') }) as Record<string, string>,
    },
  },
  test: { environment: 'jsdom', globals: true, setupFiles: ['./src/test-setup.ts'] },
}))
