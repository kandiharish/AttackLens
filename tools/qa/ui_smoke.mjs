// QA (qa_ui): read-only UI smoke via headless Chrome + the DevTools protocol (no npm dependencies; Node >= 22).
// Usage: node tools/qa/ui_smoke.mjs --base http://127.0.0.1:8038 --label demo --cdp 8039 [--out reports/qa/ui]
// Safety: every non-GET request to /api is FAILED in the browser (Fetch domain) and recorded, so the smoke can never
// upload, start a run or switch the served data. Expected values come from GET /api/* on the same base URL.
// Writes <out>/<label>_*.png and <out>/<label>_result.json; exit code 0 = all checks pass, 1 = a check failed.
import { spawn, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repo = path.resolve(here, '..', '..')
const args = process.argv.slice(2)
const opt = (k, d) => {
  const i = args.indexOf(k)
  return i >= 0 ? args[i + 1] : d
}
const BASE = opt('--base', 'http://127.0.0.1:8038').replace(/\/$/, '')
const LABEL = opt('--label', 'ui')
const CDP_PORT = Number(opt('--cdp', '8039'))
const OUT = path.resolve(repo, opt('--out', 'reports/qa/ui'))
const CHROME = opt('--chrome', 'C:/Program Files/Google/Chrome/Application/chrome.exe')
if ([8000, 5173].includes(CDP_PORT)) throw new Error('qa_ui: refusing shared port for CDP')
fs.mkdirSync(OUT, { recursive: true })

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const checks = []
const shots = []
const check = (name, ok, detail) => {
  checks.push({ name, ok: !!ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== undefined ? `  ${JSON.stringify(detail)}` : ''}`)
}

// ---------- expected values from the API (GET only) ----------
async function getJson(p) {
  const r = await fetch(BASE + p, { headers: { Accept: 'application/json' } })
  if (!r.ok) throw new Error(`${p}: ${r.status}`)
  return r.json()
}
const apiIncidents = await getJson('/api/incidents')
const apiMetrics = await getJson('/api/metrics')
const apiHealth = await getJson('/api/health')
const byRisk = [...apiIncidents].sort((a, b) => b.risk - a.risk || String(b.last_ts).localeCompare(String(a.last_ts)))
const topId = byRisk[0]?.id ?? null
const topInc = topId ? await getJson(`/api/incidents/${encodeURIComponent(topId)}`) : null

// ---------- Chrome + CDP ----------
// Fresh profile per run (pid suffix): a Chrome left over from an earlier run can keep files of the old profile locked.
const profile = path.join(repo, 'data', 'tmp', 'qa_ui', `chrome_${LABEL}_${process.pid}`)
fs.rmSync(profile, { recursive: true, force: true })
const chrome = spawn(CHROME, [
  '--headless=new', `--remote-debugging-port=${CDP_PORT}`, '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-gpu', '--hide-scrollbars=false',
  '--window-size=1920,1080', 'about:blank',
], { stdio: 'ignore' })
let targetWs = null
for (let i = 0; i < 60 && !targetWs; i++) {
  await sleep(250)
  try {
    // Chrome may bind the DevTools port on [::1] instead of 127.0.0.1 (seen on this machine): try both.
    let list = null
    for (const host of ['127.0.0.1', '[::1]']) {
      try { list = await (await fetch(`http://${host}:${CDP_PORT}/json/list`)).json(); break } catch { /* try next */ }
    }
    if (!list) throw new Error('not up')
    targetWs = list.find((t) => t.type === 'page')?.webSocketDebuggerUrl ?? null
  } catch { /* not up yet */ }
}
if (!targetWs) throw new Error('qa_ui: Chrome DevTools endpoint did not come up')
const ws = new WebSocket(targetWs)
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej })
let seq = 0
const pending = new Map()
const handlers = []
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data)
  if (m.id && pending.has(m.id)) {
    const { res, rej } = pending.get(m.id)
    pending.delete(m.id)
    m.error ? rej(new Error(`${m.error.message}`)) : res(m.result)
  } else if (m.method) handlers.forEach((h) => h(m))
}
const send = (method, params = {}) => new Promise((res, rej) => {
  const id = ++seq
  pending.set(id, { res, rej })
  ws.send(JSON.stringify({ id, method, params }))
})

const consoleErrors = []
const consoleWarnings = []
const httpErrors = []
const blockedWrites = []
handlers.push(async (m) => {
  if (m.method === 'Runtime.consoleAPICalled') {
    const text = m.params.args.map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 300)
    if (m.params.type === 'error' || m.params.type === 'assert') consoleErrors.push(text)
    if (m.params.type === 'warning') consoleWarnings.push(text)
  } else if (m.method === 'Runtime.exceptionThrown') {
    consoleErrors.push(`exception: ${m.params.exceptionDetails?.exception?.description ?? m.params.exceptionDetails?.text}`.slice(0, 300))
  } else if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
    consoleErrors.push(`log: ${m.params.entry.text} ${m.params.entry.url ?? ''}`.slice(0, 300))
  } else if (m.method === 'Network.responseReceived' && m.params.response.status >= 400) {
    httpErrors.push(`${m.params.response.status} ${m.params.response.url}`)
  } else if (m.method === 'Fetch.requestPaused') {
    const { requestId, request } = m.params
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      blockedWrites.push(`${request.method} ${request.url}`)
      await send('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' })
    } else await send('Fetch.continueRequest', { requestId })
  }
})
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/*' }] })
await send('Runtime.enable')
await send('Log.enable')
await send('Network.enable')
await send('Page.enable')

const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (r.exceptionDetails) throw new Error(`eval failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}\n${expression.slice(0, 200)}`)
  return r.result.value
}
const waitFor = async (expression, timeoutMs = 15000) => {
  const t0 = Date.now()
  while (Date.now() - t0 < timeoutMs) {
    try { if (await evaluate(expression)) return true } catch { /* page navigating */ }
    await sleep(100)
  }
  return false
}
const viewport = async (width, height) => {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false })
  await sleep(400)
}
const shot = async (name) => {
  const { data } = await send('Page.captureScreenshot', { format: 'png' })
  const file = path.join(OUT, `${LABEL}_${name}.png`)
  fs.writeFileSync(file, Buffer.from(data, 'base64'))
  shots.push(path.relative(repo, file).replaceAll('\\', '/'))
}
// Real mouse click at the element's centre (catches overlays that a DOM .click() would ignore).
const click = async (selectorExpr) => {
  const rect = await evaluate(`(() => { const el = ${selectorExpr}; if (!el) return null; el.scrollIntoView({block:'center', inline:'center'});
    const r = el.getBoundingClientRect(); return {x: r.x + r.width/2, y: r.y + r.height/2, w: r.width, h: r.height} })()`)
  if (!rect || rect.w === 0) return false
  const hit = await evaluate(`(() => { const el = ${selectorExpr}; const h = document.elementFromPoint(${rect.x}, ${rect.y}); return !!h && (h === el || el.contains(h)) })()`)
  for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased'])
    await send('Input.dispatchMouseEvent', { type, x: rect.x, y: rect.y, button: 'left', clickCount: 1 })
  await sleep(150)
  return hit
}
const key = async (k, code, vk, shift = false) => {
  for (const type of ['keyDown', 'keyUp'])
    await send('Input.dispatchKeyEvent', { type, key: k, code, windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: shift ? 8 : 0 })
  await sleep(60)
}
const hScroll = () => evaluate(`(() => { const d = document.documentElement; return {scrollWidth: d.scrollWidth, clientWidth: d.clientWidth,
  bodyScrollWidth: document.body.scrollWidth, innerWidth: window.innerWidth, h: d.scrollWidth > d.clientWidth || document.body.scrollWidth > document.body.clientWidth} })()`)
const byText = (sel, text) => `[...document.querySelectorAll(${JSON.stringify(sel)})].find(e => e.textContent.trim().startsWith(${JSON.stringify(text)}))`

const t0 = Date.now()
// ---------- 1. load ----------
await viewport(1920, 1080)
await send('Page.navigate', { url: `${BASE}/` })
const load0 = Date.now()
const listReady = await waitFor(`!!document.querySelector('nav[aria-label="Incidents"]') && (document.querySelectorAll('[data-id]').length > 0 || /No incidents in this run/.test(document.body.innerText))`, 60000)
const loadMs = Date.now() - load0
check('page loads; incident list region renders (<= 60 s; time recorded as load_ms)', listReady, { load_ms: loadMs })
await sleep(800)
const listCount = await evaluate(`document.querySelectorAll('nav[aria-label="Incidents"] [data-id]').length`)
const foundText = await evaluate(`(document.querySelector('nav[aria-label="Incidents"] .tabular-nums')||{}).textContent || ''`)
check('incident list row count == GET /api/incidents', listCount === apiIncidents.length, { ui: listCount, api: apiIncidents.length, header: foundText })
if (apiIncidents.length === 0) {
  check('empty run shows "No incidents in this run"', await evaluate(`/No incidents in this run/.test(document.body.innerText)`))
}
const statusBar = await evaluate(`(() => { const t = document.body.innerText; return t.slice(Math.max(0, t.length - 300)) })()`)
const result_pre = { load_ms: loadMs }
// Header: brand + 3 nav pills + one status dot, nothing else (user request: no clutter in header/footer).
const header = await evaluate(`(() => { const h = document.querySelector('header'); if (!h) return null;
  const focusables = [...h.querySelectorAll('a,button,input,select,textarea,[tabindex]')].filter(e => e.tabIndex >= 0 && e.offsetParent !== null);
  return { text: h.innerText.replace(/\\s+/g, ' ').trim(), nav: [...h.querySelectorAll('nav[aria-label="Views"] button')].map(b => b.textContent.trim()),
    status: h.querySelectorAll('[role=status]').length, statusLabel: h.querySelector('[role=status]')?.getAttribute('aria-label') ?? null,
    focusables: focusables.map(e => (e.getAttribute('aria-label') || e.textContent || e.tagName).trim().slice(0, 40)), height: h.getBoundingClientRect().height } })()`)
result_pre.header = header
check('header: only brand + Incidents/Add data/Connections + one status dot', !!header && header.text === 'AttackLens Incidents Add data Connections' &&
  header.nav.join('|') === 'Incidents|Add data|Connections' && header.status === 1 && header.focusables.length === 4, header)
// Footer: "<set> · <rows> events · ingested in <ingest wall> · analysed in <total wall> · AttackLens v<ver>", every number
// from run_metrics.json of the served run. Independent formatter (same documented bands as lib/metrics.ts).
const qCount = (n) => n >= 1e9 ? `${(n / 1e9).toFixed(2)} B` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)} k` : n.toLocaleString('en-US')
const qSec = (s) => { if (s < 60) return `${s.toFixed(1)} s`; const t = Math.round(s); return t < 3600 ? `${Math.floor(t / 60)}m ${t % 60}s` : `${Math.floor(t / 3600)}h ${String(Math.floor((t % 3600) / 60)).padStart(2, '0')}m` }
{
  const rmx = apiMetrics.run_metrics ?? {}
  const ingWall = (rmx.stages ?? []).find((s) => s?.name === 'ingest')?.wall_s ?? rmx.stage_stats?.ingest?.wall_s ?? null
  const rowsX = rmx.rows_in ?? rmx.stage_stats?.ingest?.rows_in ?? null
  const parts = [rowsX !== null ? `${qCount(rowsX)} events` : null, ingWall !== null ? `ingested in ${qSec(ingWall)}` : null,
    typeof rmx.total_wall_s === 'number' ? `analysed in ${qSec(rmx.total_wall_s)}` : null].filter(Boolean)
  const setName = path.basename(String(apiHealth.served_out_dir ?? '').replaceAll('\\', '/'))
  // /api/metrics may answer after the list: wait (max 10 s) until the footer shows the set name, and record the wait.
  const fw0 = Date.now()
  await waitFor(`(document.querySelector('footer')?.innerText || '').includes(${JSON.stringify(setName)})`, 10000)
  const footerWaitMs = Date.now() - fw0
  const footer = await evaluate(`(() => { const f = document.querySelector('footer'); if (!f) return null;
    return { text: f.innerText.replace(/\\s+/g, ' ').trim(), focusables: [...f.querySelectorAll('a,button,input,select,[tabindex]')].filter(e => e.tabIndex >= 0).length,
      height: f.getBoundingClientRect().height } })()`)
  const pkgVer = JSON.parse(fs.readFileSync(path.join(repo, 'frontend', 'package.json'), 'utf8')).version
  const want = ['Connected', setName, parts.join(' · '), `AttackLens v${pkgVer}`].filter(Boolean) // 'Connected' = sr-only API state
  result_pre.footer = { ui: footer, want, wait_ms: footerWaitMs, run_metrics: { rows_in: rowsX, ingest_wall_s: ingWall, total_wall_s: rmx.total_wall_s ?? null } }
  check('footer: set name + events/ingest/total times from run_metrics.json + version, nothing else', !!footer && footer.text === want.join(' ') && footer.focusables === 0, result_pre.footer)
}
await shot('01_list_1920')

// ---------- 2. top incident + tabs ----------
const result = { base: BASE, label: LABEL, served_out_dir_basename: apiHealth.served_out_dir ? path.basename(apiHealth.served_out_dir) : null,
  api_incidents: apiIncidents.length, top_id: topId, tabs: {}, keyboard: {}, viewports: {}, add_data: {}, ...result_pre }
if (topInc) {
  const firstRowId = await evaluate(`document.querySelector('nav[aria-label="Incidents"] [data-id]')?.dataset.id`)
  check('first list row is the riskiest incident', firstRowId === topId, { ui: firstRowId, api: topId })
  // Open the 2nd row then the top one, so the "opened in" timing badge is a real click measurement.
  if (apiIncidents.length > 1) {
    await click(`document.querySelectorAll('nav[aria-label="Incidents"] [data-id]')[1]`)
    await waitFor(`document.querySelector('nav[aria-label="Incidents"] [data-id][aria-current="true"]')?.dataset.id !== ${JSON.stringify(topId)}`)
    await sleep(500)
  }
  const hit = await click(`document.querySelector('nav[aria-label="Incidents"] [data-id=${JSON.stringify(topId)}]')`)
  check('top incident row is clickable (not covered)', hit)
  const opened = await waitFor(`!!document.querySelector('#incident-title') && document.querySelector('[aria-current="true"]')?.dataset.id === ${JSON.stringify(topId)}`)
  check('opening the top incident shows its workspace', opened)
  await sleep(600)
  // QA-UI-3: header "N steps across M machines" must count steps and machines over the same step set.
  const hdr = await evaluate(`(/(\\d+) steps across (\\d+) machine/.exec(document.querySelector('#incident-title')?.closest('header')?.innerText || '') || []).slice(1).map(Number)`)
  const stepsAll = [...(topInc.backbone ?? []), ...(topInc.branches ?? []).flat()]
  const hostsIn = (ss) => new Set(ss.map((s) => s.host).filter(Boolean)).size
  const consistent = [[topInc.backbone.length, hostsIn(topInc.backbone)], [stepsAll.length, hostsIn(stepsAll)]]
  result.header_counts = { ui: hdr, backbone: consistent[0], all_steps: consistent[1] }
  check('header "N steps across M machines" uses one step set [QA-UI-3]', consistent.some(([a, b]) => hdr[0] === a && hdr[1] === b), result.header_counts)
  // QA-UI-2: the status bar "Data" path should be the directory the API is serving.
  const sbData = await evaluate(`(() => { const f = document.querySelector('footer') || document.body; const s = f.querySelector('span.font-mono[title]') || [...f.querySelectorAll('span[title]')].find(e => e.querySelector('.font-mono')); return s ? s.getAttribute('title') : null })()`)
  result.status_bar_data = { ui: sbData, served_out_dir: apiHealth.served_out_dir, run_metrics_out_dir: apiMetrics.run_metrics?.out_dir ?? null }
  const norm = (p) => String(p ?? '').replaceAll('\\', '/').toLowerCase().replace(/\/$/, '')
  check('status bar Data path == /api/health served_out_dir [QA-UI-2]', norm(sbData) === norm(apiHealth.served_out_dir), result.status_bar_data)
  result.opened_in = await evaluate(`([...document.querySelectorAll('span')].find(s => /^opened in \\d+ ms/.test(s.textContent.trim()))||{}).textContent || null`)
  const tabs = await evaluate(`[...document.querySelectorAll('[role=tablist][aria-label="Incident views"] [role=tab]')].map(t => ({id: t.id, text: t.textContent.trim()}))`)
  result.tab_labels = tabs.map((t) => t.text)
  check('tablist has 6 tabs', tabs.length === 6, tabs.map((t) => t.text))
  const steps = [...(topInc.backbone ?? []), ...(topInc.branches ?? []).flat()]
  const evidenceN = steps.reduce((n, s) => n + (s.evidence?.length ?? 0), 0)
  const tabSpec = {
    overview: `!!document.querySelector('#ov-story') && document.querySelector('#ov-story').closest('section').innerText.length > 40 && !!document.querySelector('#ov-path') && !!document.querySelector('#ov-reach')`,
    steps: `document.querySelectorAll('section[aria-label="Kill chain"] ol > li').length === 15`,
    graph: `!!document.querySelector('[role=img][aria-label^="Attack graph"]') && document.querySelectorAll('[role=img][aria-label^="Attack graph"] canvas').length > 0`,
    evidence: evidenceN ? `document.querySelectorAll('#panel-evidence tbody tr').length > 0` : `/No evidence lines/.test(document.querySelector('#panel-evidence').innerText)`,
    reach: topInc.reach_next.length ? `document.querySelectorAll('#panel-reach tbody tr').length > 0` : `/No further reachable hosts/.test(document.querySelector('#panel-reach').innerText)`,
    report: `/Incident report/.test(document.querySelector('#panel-report')?.innerText || '')`,
  }
  for (const [t, cond] of Object.entries(tabSpec)) {
    const ok = await click(`document.getElementById('tab-${t}')`)
    const shown = await waitFor(`document.getElementById('tab-${t}')?.getAttribute('aria-selected') === 'true' && !!document.getElementById('panel-${t}')`, 5000)
    await sleep(t === 'graph' ? 1500 : 300)
    const content = await waitFor(cond, 8000)
    const info = { label: tabs.find((x) => x.id === `tab-${t}`)?.text }
    if (t === 'steps') {
      info.kill_chain = await evaluate(`[...document.querySelectorAll('section[aria-label="Kill chain"] ol > li button')].map(b => b.getAttribute('aria-label'))`)
      const seen = info.kill_chain.filter((l) => /: observed/.test(l)).map((l) => l.replace(/^\d+\. /, '').split(':')[0])
      const apiTactics = [...new Set([...topInc.tactics, ...steps.map((s) => s.tactic)])]
      info.observed = seen
      check('kill-chain bar: observed tactics == incident tactics', seen.length === apiTactics.length && apiTactics.every((x) => seen.some((s) => s.toLowerCase() === String(x).toLowerCase())), { ui: seen, api: apiTactics })
      const gapUi = info.kill_chain.filter((l) => /: gap/.test(l)).length
      check('kill-chain bar: gap segments == incident.gaps not observed', gapUi === topInc.gaps.filter((g) => !apiTactics.includes(g)).length, { ui: gapUi, api: topInc.gaps })
    }
    if (t === 'graph') {
      const g = await evaluate(`(() => { const box = document.querySelector('[role=img][aria-label^="Attack graph"]'); const cs = [...box.querySelectorAll('canvas')];
        let ink = 0; for (const c of cs) { try { const x = c.getContext('2d'); if (!x || !c.width) continue; const d = x.getImageData(0, 0, c.width, c.height).data;
          for (let i = 3; i < d.length; i += 16) if (d[i] > 0) ink++ } catch (e) {} }
        return {label: box.getAttribute('aria-label'), canvases: cs.length, w: box.clientWidth, h: box.clientHeight, inkSamples: ink} })()`)
      info.graph = g
      const m = /: (\d+) entities, (\d+) edges/.exec(g.label || '')
      check('graph: entity/edge counts == incident.graph', m && Number(m[1]) === topInc.graph.nodes.length && Number(m[2]) === topInc.graph.edges.length, { ui: m?.slice(1), api: [topInc.graph.nodes.length, topInc.graph.edges.length] })
      check('graph: canvas actually painted (non-transparent pixels)', g.inkSamples > 50 && g.w > 300 && g.h > 300, g)
    }
    if (t === 'evidence') {
      info.rows = await evaluate(`document.querySelectorAll('#panel-evidence tbody tr').length`)
      check('evidence: table rows == sum(step.evidence)', info.rows === evidenceN, { ui: info.rows, api: evidenceN })
    }
    if (t === 'reach') {
      info.rows = await evaluate(`document.querySelectorAll('#panel-reach tbody tr').length`)
      check('reach: table rows == incident.reach_next', info.rows === topInc.reach_next.length, { ui: info.rows, api: topInc.reach_next.length })
    }
    check(`tab ${t} opens and renders content`, ok && shown && content, info.label)
    result.tabs[t] = { clicked: ok, selected: shown, content, ...info }
    await shot(`02_tab_${t}_1920`)
  }
  // Step selection opens the inspector (level 3) — a click inside the UI, no writes.
  await click(`document.getElementById('tab-steps')`)
  await sleep(300)
  const segOk = await click(`[...document.querySelectorAll('section[aria-label="Kill chain"] ol > li button')].find(b => !b.disabled)`)
  const insp = await waitFor(`!!document.querySelector('aside[aria-label="Inspector"]')`, 4000)
  check('kill-chain segment click opens the step inspector', segOk && insp)
  await shot('03_inspector_1920')
  await click(`document.querySelector('aside[aria-label="Inspector"] button[aria-label="Close details"]')`)
}

// ---------- 3. keyboard navigation ----------
await send('Page.navigate', { url: `${BASE}/${topId ? `#${encodeURIComponent(topId)}` : ''}` })
await waitFor(`!!document.querySelector('nav[aria-label="Incidents"]')`)
await sleep(1200)
await evaluate(`document.activeElement && document.activeElement.blur(), window.focus(), 1`)
const seen = []
for (let i = 0; i < 45; i++) {
  await key('Tab', 'Tab', 9)
  seen.push(await evaluate(`(() => { const e = document.activeElement; if (!e || e === document.body) return 'body';
    const s = getComputedStyle(e); const ring = s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0 || s.boxShadow !== 'none';
    return [e.tagName.toLowerCase(), e.id ? '#' + e.id : '', e.getAttribute('role') ? '[' + e.getAttribute('role') + ']' : '', e.dataset.id ? '[row]' : '',
      ' ', (e.getAttribute('aria-label') || e.getAttribute('placeholder') || e.textContent || '').trim().slice(0, 32), ring ? ' (ring)' : ' (NO RING)'].join('') })()`))
}
result.keyboard.tab_order = seen
const reached = (re) => seen.some((s) => re.test(s))
const want = { 'nav Incidents': /^button.*Incidents/, 'nav Add data': /^button.*Add data/, 'nav Connections': /^button.*Connections/, 'header status dot': /\[status\]/, 'search input': /^input.*Search host/, 'sort select': /^select/ }
if (apiIncidents.length) want['incident row'] = /\[row\]/
if (topId) want['incident tab (roving tabindex)'] = /#tab-/
for (const [n, re] of Object.entries(want)) check(`keyboard: Tab reaches ${n}`, reached(re))
const noRing = seen.filter((s) => s.endsWith('(NO RING)'))
check('keyboard: every focused control shows a focus indicator', noRing.length === 0, noRing.slice(0, 5))
if (topId) {
  await evaluate(`document.getElementById('tab-overview')?.focus(), 1`)
  await key('ArrowRight', 'ArrowRight', 39)
  const arrow = await evaluate(`document.activeElement?.id + ':' + document.activeElement?.getAttribute('aria-selected')`)
  check('keyboard: ArrowRight in tablist moves to next tab', arrow === 'tab-steps:true', arrow)
  if (apiIncidents.length > 1) {
    await evaluate(`document.querySelector('nav[aria-label="Incidents"] [data-id][aria-current="true"]')?.focus(), 1`)
    await key('ArrowDown', 'ArrowDown', 40)
    await sleep(400)
    const cur = await evaluate(`document.querySelector('nav[aria-label="Incidents"] [aria-current="true"]')?.dataset.id`)
    check('keyboard: ArrowDown in incident list selects the next row', cur === byRisk[1].id, { ui: cur, want: byRisk[1].id })
  }
}

// ---------- 4. Add data page ----------
await send('Page.navigate', { url: `${BASE}/` })
await waitFor(`!!document.querySelector('nav[aria-label="Views"]')`)
await sleep(800)
const navOk = await click(byText('nav[aria-label="Views"] button', 'Add data'))
const addOk = await waitFor(`/Add your own logs/.test(document.body.innerText)`, 6000)
check('Add data view opens from the top nav', navOk && addOk)
await sleep(800)
const add = await evaluate(`(() => { const t = document.body.innerText; const btn = (s) => [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith(s));
  const pathInput = [...document.querySelectorAll('form input')][0]; const submit = document.querySelector('form button[type=submit]');
  return { chooseLogs: !!document.getElementById('step-1-title'), analyse: !!document.getElementById('step-2-title'),
    dropZone: /Drop log files here/.test(t), browseBtn: [...document.querySelectorAll('button')].filter(b => !b.disabled && /brows|choose files|select files/i.test(b.textContent)).map(b => b.textContent.trim()), fileInput: !!document.querySelector('input[type=file]'),
    pathForm: !!pathInput, pathSubmitDisabledWhenEmpty: !!submit && submit.disabled, analyseDisabled: !!btn('Analyse these logs') && btn('Analyse these logs').disabled,
    coverageCard: !!document.querySelector('section[aria-label="Detection coverage"]'), coverageText: document.querySelector('section[aria-label="Detection coverage"]')?.innerText ?? null,
    offlineBanner: document.querySelector('[role=alert]')?.innerText ?? null, recentUploads: !!document.getElementById('recent-uploads') } })()`)
result.add_data = add
check('Add data: both options render (upload drop zone + local path form)', add.dropZone && add.fileInput && add.pathForm, add)
check('Add data: path submit disabled while empty; Analyse disabled with no source', add.pathSubmitDisabledWhenEmpty && add.analyseDisabled)
// Coverage card logic: the UI (lib/addData.readSigma) reads run_metrics.sigma_* top-level keys; DEVELOPMENT.md 15.6
// documents them under run_metrics.stage_stats.detect. Record both expectations; the check uses the documented contract.
const rm = apiMetrics.run_metrics ?? {}
const det = rm.stage_stats?.detect ?? {}
const isNum = (v) => typeof v === 'number' && Number.isFinite(v)
const uiExpects = isNum(rm.sigma_rules_total) && isNum(rm.sigma_rules_applicable)
const docExpects = isNum(det.sigma_rules_total) && isNum(det.sigma_rules_applicable)
result.add_data.coverage = { shown: add.coverageCard, ui_logic_expects: uiExpects, documented_contract_expects: docExpects,
  stage_stats_detect: docExpects ? { total: det.sigma_rules_total, applicable: det.sigma_rules_applicable, compiled: det.sigma_rules_compiled, alerts: det.sigma_alerts } : null }
check('Add data: coverage card visibility matches the frontend readSigma() logic', add.coverageCard === uiExpects, result.add_data.coverage)
check('Add data: coverage card shown when run_metrics.stage_stats.detect has sigma keys (DEVELOPMENT.md 15.6) [QA-UI-1]', add.coverageCard === docExpects, result.add_data.coverage)
await shot('04_add_data_1920')

// ---------- 5. viewports: no horizontal scroll ----------
for (const [w, h] of [[1366, 768], [1920, 1080]]) {
  const vp = `${w}x${h}`
  result.viewports[vp] = {}
  await viewport(w, h)
  await send('Page.navigate', { url: `${BASE}/${topId ? `#${encodeURIComponent(topId)}` : ''}` })
  await waitFor(`!!document.querySelector('nav[aria-label="Incidents"]')`)
  await sleep(1500)
  const views = topId ? ['overview', 'steps', 'graph', 'evidence', 'reach', 'report'] : ['list']
  for (const v of views) {
    if (v !== 'list') {
      await click(`document.getElementById('tab-${v}')`)
      await sleep(v === 'graph' ? 1200 : 400)
    }
    const s = await hScroll()
    const tl = await evaluate(`(() => { const t = document.querySelector('[role=tablist][aria-label="Incident views"]'); return t ? {sw: t.scrollWidth, cw: t.clientWidth} : null })()`)
    result.viewports[vp][v] = { ...s, tablist: tl }
    check(`${vp} ${v}: no horizontal page scroll`, !s.h, s)
    if (tl) check(`${vp} ${v}: all incident tabs visible without scrolling the tab strip`, tl.sw <= tl.cw + 1, tl)
    if (v === 'overview' || v === 'graph' || v === 'list') await shot(`05_${vp}_${v}`)
  }
  await click(byText('nav[aria-label="Views"] button', 'Add data'))
  await waitFor(`/Add your own logs/.test(document.body.innerText)`, 5000)
  await sleep(500)
  const s = await hScroll()
  result.viewports[vp].add_data = s
  check(`${vp} add-data: no horizontal page scroll`, !s.h, s)
  await shot(`05_${vp}_add_data`)
}


// ---------- 5b. RunStepper dev harness (/?harness=run-stepper): ETA + ingestion timing render, no API calls ----------
if (!process.argv.includes('--no-harness')) {
  await viewport(1366, 768)
  await send('Page.navigate', { url: `${BASE}/?harness=run-stepper` })
  const hOk = await waitFor(`/RunStepper harness/.test(document.body.innerText)`, 45000)
  await sleep(600)
  const h = await evaluate(`(() => { const secs = [...document.querySelectorAll('section.card')];
    return secs.map(s => ({ title: s.querySelector('.section-label')?.textContent.trim() ?? null,
      headline: s.querySelector('p.headline')?.textContent.trim() ?? null,
      ingest: [...s.querySelectorAll('p.font-mono')].map(p => p.textContent.trim()).find(t => t.startsWith('Ingestion:')) ?? null,
      bar: s.querySelector('[role=progressbar]')?.getAttribute('aria-valuenow') ?? null,
      elapsed: (/Elapsed (\S+(?: \S+)?)/.exec(s.innerText) || [])[1] ?? null,
      rows: [...s.querySelectorAll('tbody tr')].map(r => [...r.children].map(c => c.textContent.trim())) })) })()`)
  result.harness = h
  // Expected headlines hand-derived from the harness cases: eta 371 s -> 6 min; null -> Estimating; 6 s -> Finishing;
  // succeeded 548.3 s -> 9m 8s; failed 402 s -> 6m 42s.
  // Old backend (eta_s key absent): no headline at all (RunStepper.tsx, 02:12 change).
  const wantH = [null, 'About 6 min remaining', 'Estimating time…', 'Finishing…', 'Finished in 9m 8s', 'Stopped after 6m 42s']
  check('harness: RunStepper headlines (ETA / finished / stopped) exact', hOk && JSON.stringify(h.slice(0, 6).map((x) => x.headline)) === JSON.stringify(wantH), { ui: h.slice(0, 6).map((x) => x.headline), want: wantH })
  check('harness: ingest line exact while Reading; absent on old backend', h[1]?.ingest === 'Ingestion: 3.20 GB of 6.50 GB · 31 MB/s' && h[0]?.ingest === null, { case0: h[0]?.ingest, case1: h[1]?.ingest })
  check('harness: ingest stage fraction 0.49 -> progressbar 49; no bar when fraction is null', h[1]?.bar === '49' && h[2]?.bar === null, { case1: h[1]?.bar, case2: h[2]?.bar })
  // Smoothing table: shown column must equal the hand-computed EMA (see backend/tests/qa/test_qa_ui_timing.py).
  const shown = (h[6]?.rows ?? []).map((r) => r[3])
  const wantS = ['null', '420.0', '404.7', '485.6', '419.4', '414.8', '583.3', '678.9', '440.0']
  check('harness: ETA smoothing table == hand-computed EMA with 20 % cap', JSON.stringify(shown) === JSON.stringify(wantS), { ui: shown, want: wantS })
  const hs = await hScroll()
  check('1366x768 harness: no horizontal page scroll', !hs.h, hs)
  await shot('06_harness_run_stepper_1366')
}

// ---------- 6. console + safety ----------
await sleep(500)
check('no console errors / uncaught exceptions', consoleErrors.length === 0, consoleErrors.slice(0, 10))
check('no HTTP >= 400 responses', httpErrors.length === 0, httpErrors.slice(0, 10))
check('read-only: no non-GET /api request was attempted', blockedWrites.length === 0, blockedWrites)
Object.assign(result, { status_bar_tail: statusBar, console_errors: consoleErrors, console_warnings: consoleWarnings.slice(0, 20), http_errors: httpErrors,
  blocked_writes: blockedWrites, checks, screenshots: shots, wall_s: (Date.now() - t0) / 1000 })
fs.writeFileSync(path.join(OUT, `${LABEL}_result.json`), JSON.stringify(result, null, 2))
const failed = checks.filter((c) => !c.ok)
console.log(`\n${LABEL}: ${checks.length - failed.length}/${checks.length} checks pass; screenshots: ${shots.length}; wall ${result.wall_s}s`)
ws.close()
// Windows: chrome.kill() ends only the launcher; kill the whole tree so the CDP port and profile are freed.
if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(chrome.pid), '/T', '/F'], { stdio: 'ignore' })
else chrome.kill()
process.exit(failed.length ? 1 : 0)
