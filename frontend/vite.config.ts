import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// /api -> FastAPI backend (uvicorn attacklens.api:app --port 8000).
// Mock mode: VITE_USE_MOCK=true makes src/api.ts read src/mock/*.json and never fetch.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Served locally for an offline demo; cytoscape alone is ~500 kB minified.
  build: { chunkSizeWarningLimit: 1000 },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
