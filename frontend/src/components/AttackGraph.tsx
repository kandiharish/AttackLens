import cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { useEffect, useRef, useState } from 'react'
import { truncate } from '../lib/format'
import type { GraphEdge, GraphNode } from '../types'

cytoscape.use(dagre)

interface Props {
  nodes: GraphNode[]
  edges: GraphEdge[]
  highlighted: number | null
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

const SHAPE: Record<GraphNode['type'], string> = {
  host: 'round-rectangle',
  user: 'ellipse',
  ip: 'diamond',
  domain: 'hexagon',
}

const COLOR: Record<GraphNode['type'], string> = {
  host: '#1e3a5f',
  user: '#3b2a63',
  ip: '#134e4a',
  domain: '#5b3a12',
}

function inferType(id: string): GraphNode['type'] {
  const p = id.split(':', 1)[0]
  return p === 'user' || p === 'ip' || p === 'domain' ? p : 'host'
}

export function AttackGraph({ nodes, edges, highlighted, whyForStep, onSelectStep }: Props) {
  const box = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [tip, setTip] = useState<Tip | null>(null)
  // Callbacks change identity per render; keep the latest in refs so the graph is built once per data set.
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

    const cy = cytoscape({
      container: box.current,
      elements: [
        ...allNodes.map((n) => ({
          group: 'nodes' as const,
          data: { id: n.id, label: n.label, type: n.type, shape: SHAPE[n.type] ?? 'round-rectangle', color: COLOR[n.type] ?? '#1e293b' },
          classes: n.compromised ? 'compromised' : '',
        })),
        ...edges.map((e, i) => ({
          group: 'edges' as const,
          data: { id: `edge-${i}`, source: e.source, target: e.target, step: e.step, tech: e.label, label: `${e.step + 1} · ${e.label}` },
        })),
      ],
      style: [
        {
          selector: 'node',
          style: {
            shape: 'data(shape)' as never,
            'background-color': 'data(color)',
            'border-width': 2,
            'border-color': '#475569',
            label: 'data(label)',
            color: '#e2e8f0',
            'font-size': 11,
            'font-family': 'ui-monospace, Consolas, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 5,
            width: 38,
            height: 38,
          },
        },
        {
          selector: 'node.compromised',
          style: { 'border-color': '#f43f5e', 'border-width': 4, 'background-color': '#4c0519', color: '#fecdd3', 'font-weight': 'bold' },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 10,
            'font-family': 'ui-monospace, Consolas, monospace',
            color: '#bae6fd',
            'text-background-color': '#0f172a',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-rotation': 'autorotate',
          },
        },
        {
          selector: 'edge.hl, edge:selected',
          style: { width: 4, 'line-color': '#38bdf8', 'target-arrow-color': '#38bdf8', color: '#ffffff', 'z-index': 10 },
        },
      ],
      layout: { name: 'dagre', rankDir: 'LR', nodeSep: 40, rankSep: 110, edgeSep: 20, padding: 24 } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.2,
      minZoom: 0.3,
      maxZoom: 2.5,
      autoungrabify: false,
      boxSelectionEnabled: false,
    })
    cyRef.current = cy

    cy.on('mouseover', 'edge', (evt) => {
      const step = Number(evt.target.data('step'))
      const p = evt.renderedPosition ?? evt.target.renderedMidpoint()
      const why = whyRef.current(step)
      setTip({ x: p.x, y: p.y, title: `Step ${step + 1} · ${String(evt.target.data('tech'))}`, text: why ?? 'no link reason recorded (entry or unlinked step)' })
      box.current?.style.setProperty('cursor', 'pointer')
    })
    cy.on('mouseout', 'edge', () => {
      setTip(null)
      box.current?.style.setProperty('cursor', 'default')
    })
    cy.on('tap', 'edge', (evt) => selectRef.current(Number(evt.target.data('step'))))

    const ro = new ResizeObserver(() => {
      cy.resize()
      cy.fit(undefined, 24)
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
    cy.edges().removeClass('hl')
    if (highlighted !== null) cy.edges().filter((e) => Number(e.data('step')) === highlighted).addClass('hl')
  }, [highlighted, nodes, edges])

  return (
    <section aria-label="Attack graph">
      <div className="mb-1.5 flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Attack graph</h3>
        <Legend />
      </div>
      <div className="relative">
        <div
          ref={box}
          className="h-72 w-full rounded-md border border-slate-800 bg-slate-950"
          role="img"
          aria-label={`Attack graph left to right: ${nodes.length} entities, ${edges.length} edges. Hover an edge for why it is linked, click to jump to the step.`}
        />
        {tip && (
          <div
            role="tooltip"
            className="pointer-events-none absolute z-10 max-w-xs -translate-x-1/2 -translate-y-full rounded border border-sky-700 bg-slate-900/95 px-2 py-1 text-[11px] shadow-lg"
            style={{ left: tip.x, top: tip.y - 8 }}
          >
            <div className="font-mono font-semibold text-sky-200">{tip.title}</div>
            <div className="text-slate-300">{truncate(tip.text)}</div>
          </div>
        )}
      </div>
    </section>
  )
}

function Legend() {
  const item = (shape: React.ReactNode, label: string) => (
    <span className="flex items-center gap-1">
      <svg viewBox="0 0 14 14" className="h-3 w-3" aria-hidden="true">
        {shape}
      </svg>
      {label}
    </span>
  )
  return (
    <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
      {item(<rect x="1" y="2" width="12" height="10" rx="3" fill={COLOR.host} stroke="#94a3b8" />, 'host')}
      {item(<circle cx="7" cy="7" r="5.5" fill={COLOR.user} stroke="#94a3b8" />, 'user')}
      {item(<path d="M7 1l6 6-6 6-6-6z" fill={COLOR.ip} stroke="#94a3b8" />, 'ip')}
      {item(<path d="M4 1.5h6L13 7l-3 5.5H4L1 7z" fill={COLOR.domain} stroke="#94a3b8" />, 'domain')}
      {item(<circle cx="7" cy="7" r="5" fill="#4c0519" stroke="#f43f5e" strokeWidth="2.5" />, 'compromised')}
      <span>edge label = step · technique</span>
    </div>
  )
}
