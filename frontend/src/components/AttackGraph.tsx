import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { useEffect, useRef, useState } from 'react'
import { isFirewall } from '../lib/entity'
import { truncate } from '../lib/format'
import type { GraphEdge, GraphNode } from '../types'

cytoscape.use(dagre)

interface Props {
  nodes: GraphNode[]
  edges: GraphEdge[]
  selected: number | null
  /** why-linked text for the step an edge belongs to (null if none recorded). */
  whyForStep: (step: number) => string | null
  onSelectStep: (step: number) => void
}

interface Tip {
  x: number
  y: number
  title: string
  text: string
}

const SHAPE: Record<GraphNode['type'], string> = { host: 'round-rectangle', user: 'ellipse', ip: 'diamond', domain: 'hexagon' }

const C = {
  ink: '#0A0A0A',
  ink2: '#3D3F3B',
  muted: '#6B6E68',
  line: '#D6D4CC',
  accent: '#027A47',
  brand: '#04DB7F',
  crit: '#DC4A3A',
  critBg: '#FDF0EE',
  high: '#E89B5C',
  highBg: '#FDF3EA',
  user: '#EAFBF3',
  userLine: '#03B86B',
  ip: '#F5F4EE',
  ipLine: '#8A8D85',
  domain: '#FAFCFA',
}

/** Auto-fit never zooms past this (a 4-node graph should not fill a 1920 px screen). */
const MAX_FIT_ZOOM = 1.3

function inferType(id: string): GraphNode['type'] {
  const p = id.split(':', 1)[0]
  return p === 'user' || p === 'ip' || p === 'domain' ? p : 'host'
}

function fill(t: GraphNode['type']): [string, string] {
  if (t === 'user') return [C.user, C.userLine]
  if (t === 'ip') return [C.ip, C.ipLine]
  if (t === 'domain') return [C.domain, C.muted]
  return ['#FFFFFF', C.line]
}

export function AttackGraph({ nodes, edges, selected, whyForStep, onSelectStep }: Props) {
  const box = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [tip, setTip] = useState<Tip | null>(null)
  const whyRef = useRef(whyForStep)
  const selectRef = useRef(onSelectStep)
  useEffect(() => {
    whyRef.current = whyForStep
    selectRef.current = onSelectStep
  })

  useEffect(() => {
    if (!box.current) return
    const known = new Set(nodes.map((n) => n.id))
    const implicit: GraphNode[] = []
    for (const e of edges) {
      for (const id of [e.source, e.target]) {
        if (!known.has(id)) {
          known.add(id)
          implicit.push({ id, type: inferType(id), label: id.slice(id.indexOf(':') + 1), compromised: false })
        }
      }
    }
    const allNodes = [...nodes, ...implicit]
    const dense = allNodes.length > 10

    // Fan-out (one source -> many targets, same step + technique, e.g. a scan): label only the first edge.
    const seenFan = new Set<string>()
    const edgeEls = edges.map((e, i) => {
      const fanKey = `${e.source}|${e.step}|${e.label}`
      const repeat = seenFan.has(fanKey)
      seenFan.add(fanKey)
      return {
        group: 'edges' as const,
        data: { id: `edge-${i}`, source: e.source, target: e.target, step: e.step, tech: e.label, label: repeat ? '' : `${e.step + 1} · ${e.label}` },
        classes: repeat ? 'fan' : '',
      }
    })

    const cy = cytoscape({
      container: box.current,
      elements: [
        ...allNodes.map((n) => {
          const fw = n.type === 'host' && (isFirewall(n.id) || isFirewall(n.label))
          const [bg, border] = fw ? [C.highBg, C.high] : fill(n.type)
          return {
            group: 'nodes' as const,
            data: { id: n.id, label: fw ? `${n.label}\nfirewall` : n.label, shape: fw ? 'round-rectangle' : (SHAPE[n.type] ?? 'round-rectangle'), bg, border },
            classes: [n.compromised ? 'compromised' : '', fw ? 'firewall' : '', n.type].join(' ').trim(),
          }
        }),
        ...edgeEls,
      ],
      style: [
        {
          selector: 'node',
          style: {
            shape: 'data(shape)' as never,
            'background-color': 'data(bg)',
            'border-width': 1.5,
            'border-color': 'data(border)',
            label: 'data(label)',
            color: C.ink,
            'font-size': dense ? 10 : 11,
            'font-family': 'Geist Mono Variable, Cascadia Mono, Consolas, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-wrap': 'wrap',
            'text-max-width': '150px',
            'text-background-color': '#FFFFFF',
            'text-background-opacity': 0.85,
            'text-background-padding': '1px',
            width: dense ? 26 : 34,
            height: dense ? 26 : 34,
          },
        },
        { selector: 'node.host', style: { width: dense ? 34 : 44, height: dense ? 24 : 30 } },
        { selector: 'node.firewall', style: { 'border-width': 2, color: '#A54800', 'font-weight': 'bold' } },
        { selector: 'node.compromised', style: { 'background-color': C.critBg, 'border-color': C.crit, 'border-width': 2.5, color: '#AE2E24', 'font-weight': 'bold' } },
        {
          selector: 'edge',
          style: {
            width: 1.25,
            'line-color': C.muted,
            'target-arrow-color': C.muted,
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 10,
            'font-family': 'Geist Mono Variable, Cascadia Mono, Consolas, monospace',
            color: C.ink2,
            'text-background-color': '#FFFFFF',
            'text-background-opacity': 1,
            'text-background-padding': '2px',
            'text-border-width': 1,
            'text-border-color': '#DFE1E6',
            'text-border-opacity': 1,
            'text-rotation': 'autorotate',
          },
        },
        { selector: 'edge.fan', style: { width: 0.75, 'line-color': C.line, 'target-arrow-color': C.line } },
        { selector: 'edge.sel', style: { width: 3, 'line-color': C.userLine, 'target-arrow-color': C.userLine, color: C.ink, 'text-border-color': C.brand, 'text-background-color': '#EAFBF3', 'z-index': 10 } },
        { selector: 'edge.hover', style: { width: 2.5, 'line-color': C.ink, 'target-arrow-color': C.ink } },
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: dense ? 22 : 44, rankSep: dense ? 130 : 120, edgeSep: 12, padding: 32 } as cytoscape.LayoutOptions,
      minZoom: 0.2,
      maxZoom: 3,
      boxSelectionEnabled: false,
    })
    cyRef.current = cy

    cy.on('mouseover', 'edge', (evt) => {
      const step = Number(evt.target.data('step'))
      const p = evt.renderedPosition ?? evt.target.renderedMidpoint()
      evt.target.addClass('hover')
      setTip({ x: p.x, y: p.y, title: `Step ${step + 1} · ${String(evt.target.data('tech'))}`, text: whyRef.current(step) ?? 'no link reason recorded (entry or unlinked step)' })
      if (box.current) box.current.style.cursor = 'pointer'
    })
    cy.on('mouseout', 'edge', (evt) => {
      evt.target.removeClass('hover')
      setTip(null)
      if (box.current) box.current.style.cursor = 'default'
    })
    cy.on('tap', 'edge', (evt) => selectRef.current(Number(evt.target.data('step'))))

    const fitCapped = () => {
      cy.fit(undefined, 32)
      if (cy.zoom() > MAX_FIT_ZOOM) {
        cy.zoom(MAX_FIT_ZOOM)
        cy.center()
      }
    }
    fitCapped()
    const ro = new ResizeObserver(() => {
      cy.resize()
      fitCapped()
    })
    ro.observe(box.current)
    return () => {
      ro.disconnect()
      cy.destroy()
      cyRef.current = null
    }
  }, [nodes, edges])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.edges().removeClass('sel')
    if (selected !== null) cy.edges().filter((e) => Number(e.data('step')) === selected).addClass('sel')
  }, [selected, nodes, edges])

  const zoom = (f: number) => {
    const cy = cyRef.current
    if (!cy) return
    cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } })
  }
  const fit = () => {
    const cy = cyRef.current
    if (!cy) return
    cy.fit(undefined, 32)
    if (cy.zoom() > MAX_FIT_ZOOM) {
      cy.zoom(MAX_FIT_ZOOM)
      cy.center()
    }
  }

  const ctl = 'focus-ring flex h-8 w-8 items-center justify-center border-line text-[15px] text-ink hover:bg-subtle'
  return (
    <div className="relative h-full min-h-[320px] overflow-hidden rounded-2xl border border-line">
      <div
        ref={box}
        className="dot-grid h-full w-full"
        role="img"
        aria-label={`Attack graph, left to right: ${nodes.length} entities, ${edges.length} edges. Hover an edge for why it is linked; click it to select the step.`}
      />
      <div className="absolute top-3 right-3 flex overflow-hidden rounded-full border border-line-strong bg-white shadow-card">
        <button type="button" className={`${ctl} border-r`} onClick={() => zoom(1.25)} title="Zoom in" aria-label="Zoom in">+</button>
        <button type="button" className={`${ctl} border-r`} onClick={() => zoom(0.8)} title="Zoom out" aria-label="Zoom out">−</button>
        <button type="button" className={`${ctl} w-auto px-3 text-[12px] font-medium`} onClick={fit} title="Fit to view">
          Fit
        </button>
      </div>
      <Legend />
      {tip && (
        <div
          role="tooltip"
          className="pointer-events-none absolute z-10 max-w-xs -translate-x-1/2 -translate-y-full rounded-xl border border-line bg-white px-3 py-2 text-[12px] shadow-pop"
          style={{ left: tip.x, top: tip.y - 10 }}
        >
          <div className="font-mono font-semibold text-ink">{tip.title}</div>
          <div className="mt-0.5 text-ink-2 italic">{truncate(tip.text)}</div>
        </div>
      )}
    </div>
  )
}

function Legend() {
  const item = (shape: React.ReactNode, label: string) => (
    <span className="flex items-center gap-1.5">
      <svg viewBox="0 0 14 14" className="h-3.5 w-3.5" aria-hidden="true">
        {shape}
      </svg>
      {label}
    </span>
  )
  return (
    <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-full border border-line bg-white/95 px-4 py-1.5 text-[12px] text-ink-2 shadow-card">
      {item(<rect x="1" y="3" width="12" height="8" rx="2" fill="#fff" stroke={C.line} strokeWidth="1.5" />, 'host')}
      {item(<circle cx="7" cy="7" r="5.5" fill={C.user} stroke={C.userLine} strokeWidth="1.5" />, 'user')}
      {item(<path d="M7 1l6 6-6 6-6-6z" fill={C.ip} stroke={C.ipLine} strokeWidth="1.5" />, 'ip')}
      {item(<path d="M4 1.5h6L13 7l-3 5.5H4L1 7z" fill={C.domain} stroke={C.muted} strokeWidth="1.5" />, 'domain')}
      {item(<rect x="1" y="3" width="12" height="8" rx="2" fill={C.highBg} stroke={C.high} strokeWidth="1.5" />, 'firewall')}
      {item(<rect x="1" y="3" width="12" height="8" rx="2" fill={C.critBg} stroke={C.crit} strokeWidth="2" />, 'compromised')}
      <span className="text-muted">arrows = step · technique · hover for why</span>
    </div>
  )
}
