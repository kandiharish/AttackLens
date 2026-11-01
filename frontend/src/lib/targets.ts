// PRD §4 targets (docs/PRD.md): Good / Great thresholds used to grade the KPI tiles.
// The numbers graded here always come from /api/metrics; only the thresholds are fixed (they are the rules).

export type Grade = 'great' | 'good' | 'below' | 'none'

interface Target {
  good: number
  great: number
  higherIsBetter: boolean
  text: string
}

export const TARGETS = {
  detection: { good: 70, great: 90, higherIsBetter: true, text: 'Good > 70 % · Great > 90 %' },
  labels: { good: 60, great: 85, higherIsBetter: true, text: 'Good > 60 % · Great > 85 %' },
  rebuilt: { good: 50, great: 100, higherIsBetter: true, text: 'Good ≥ half · Great = all' },
  falseAlarms: { good: 30, great: 10, higherIsBetter: false, text: 'Good < 30 % · Great < 10 %' },
  peakRamMb: { good: 16 * 1024, great: 8 * 1024, higherIsBetter: false, text: 'Good < 16 GB · Great < 8 GB' },
  runTimeS: { good: 3 * 3600, great: 3600, higherIsBetter: false, text: 'Good < 3 h · Great < 1 h' },
  openPathMs: { good: 2000, great: 500, higherIsBetter: false, text: 'Good < 2 s · Great < 500 ms' },
} satisfies Record<string, Target>

export function grade(value: number | null, t: Target): Grade {
  if (value === null) return 'none'
  if (t.higherIsBetter) {
    // rebuilt uses ≥ (half / all); the others are strict >
    const strict = t !== TARGETS.rebuilt
    const ge = (v: number, x: number) => (strict ? v > x : v >= x)
    if (ge(value, t.great)) return 'great'
    if (ge(value, t.good)) return 'good'
    return 'below'
  }
  if (value < t.great) return 'great'
  if (value < t.good) return 'good'
  return 'below'
}
