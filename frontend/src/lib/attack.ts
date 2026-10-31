// ATT&CK v20 enterprise tactic order (15 tactics; Defense Evasion split into Stealth + Defense Impairment).
export const TACTICS_V20 = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Stealth',
  'Defense Impairment',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const

const norm = (s: string) => s.trim().toLowerCase()

/** Position of a tactic in the v20 order; unknown tactics sort last. */
export function tacticIndex(tactic: string): number {
  const i = TACTICS_V20.findIndex((t) => norm(t) === norm(tactic))
  return i < 0 ? TACTICS_V20.length : i
}

export function sameTactic(a: string, b: string): boolean {
  return norm(a) === norm(b)
}
