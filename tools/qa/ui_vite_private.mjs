// QA (qa_ui): start a PRIVATE Vite dev server for the read-only UI smoke without touching frontend/ or :5173.
// Usage: node tools/qa/ui_vite_private.mjs --port 8038 --api http://127.0.0.1:8037 [--mock]
// - Loads frontend/vite.config.ts unchanged and only overrides port, /api proxy target and cacheDir.
// - cacheDir lives under data/tmp so the shared dev server's node_modules/.vite cache is never rewritten.
import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repo = path.resolve(here, '..', '..')
const frontend = path.join(repo, 'frontend')

const args = process.argv.slice(2)
const opt = (k, d) => {
  const i = args.indexOf(k)
  return i >= 0 ? args[i + 1] : d
}
const port = Number(opt('--port', '8038'))
const api = opt('--api', 'http://127.0.0.1:8037')
const mock = args.includes('--mock')
if (port === 5173 || /:8000\b/.test(api)) throw new Error('qa_ui: refusing shared ports 5173/8000')

const req = createRequire(path.join(frontend, 'package.json'))
const vite = await import(pathToFileURL(req.resolve('vite')).href)
if (mock) process.env.VITE_USE_MOCK = 'true'

const server = await vite.createServer({
  root: frontend,
  configFile: path.join(frontend, 'vite.config.ts'),
  cacheDir: path.join(repo, 'data', 'tmp', 'qa_ui', mock ? 'vite_cache_mock' : 'vite_cache'),
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port,
    strictPort: true,
    proxy: { '/api': { target: api, changeOrigin: true } },
  },
})
await server.listen()
console.log(`qa_ui vite listening on http://127.0.0.1:${port} (api -> ${api}, mock=${mock})`)
