// Pure helpers over one Incident (contract types only).
import type { Incident, PathEdge, ReachNext, Step } from '../types'

export function allSteps(inc: Incident): Step[] {
  return [...inc.backbone, ...inc.branches.flat()].sort((a, b) => a.step - b.step)
}

export function stepByEpisode(inc: Incident): Map<string, Step> {
  return new Map(allSteps(inc).map((s) => [s.episode_id, s]))
}

/** Link explaining why `to` follows `from` (exact pair first, else any edge into `to`). */
export function linkInto(edges: PathEdge[], from: Step | undefined, to: Step): PathEdge | undefined {
  return (from && edges.find((e) => e.from === from.episode_id && e.to === to.episode_id)) || edges.find((e) => e.to === to.episode_id)
}

export function edgesIn(inc: Incident, s: Step): PathEdge[] {
  return inc.edges.filter((e) => e.to === s.episode_id)
}

export function edgesOut(inc: Incident, s: Step): PathEdge[] {
  return inc.edges.filter((e) => e.from === s.episode_id)
}

export function techniqueOf(s: Step): string {
  return s.sub_technique_id ?? s.technique_id
}

export function hostsOf(inc: Incident): string[] {
  return [...new Set(allSteps(inc).map((s) => s.host).filter((h): h is string => !!h))]
}

/** Reach-next order: untouched first (where the attacker goes next), then hops, crown jewels first, host. */
export function sortReach(rows: ReachNext[]): ReachNext[] {
  return [...rows].sort(
    (a, b) =>
      Number(a.touched) - Number(b.touched) ||
      a.hops - b.hops ||
      Number(b.crown_jewel !== null) - Number(a.crown_jewel !== null) ||
      a.host.localeCompare(b.host),
  )
}
