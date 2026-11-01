// Plain-language layer for judges: friendly step names, one-line explanations, and incident titles built
// from the data. Wording only; every fact (technique, host, counts) still comes from the API.
import { tacticIndex } from './attack'
import type { Incident, IncidentSummary, Step } from '../types'

interface Plain {
  /** short verb phrase for a step card ("Password guessing") */
  short: string
  /** one-line explanation for tooltips ("trying many passwords until one works") */
  explain: string
}

/** Parent ATT&CK technique -> plain wording. Unknown ids fall back to the data's technique_name. */
const BY_TECHNIQUE: Record<string, Plain> = {
  T1110: { short: 'Password guessing', explain: 'trying many passwords until one works' },
  T1078: { short: 'Logged in', explain: 'using a real account (stolen or guessed) to log in' },
  T1133: { short: 'Logged in remotely', explain: 'coming in through VPN or another remote-access service' },
  T1190: { short: 'Broke into a public app', explain: 'exploiting a weakness in an internet-facing application' },
  T1566: { short: 'Phishing email', explain: 'tricking a user with a malicious email' },
  T1021: { short: 'Moved to another machine', explain: 'using remote services (RDP, SMB, SSH) to reach another host' },
  T1059: { short: 'Ran commands', explain: 'running scripts or shell commands (e.g. PowerShell)' },
  T1204: { short: 'User opened a file', explain: 'a user ran a malicious file or link' },
  T1087: { short: 'Looked up accounts', explain: 'listing users and admin groups' },
  T1046: { short: 'Scanned the network', explain: 'probing many machines and ports to find services' },
  T1018: { short: 'Found other machines', explain: 'discovering hosts on the network' },
  T1083: { short: 'Browsed files', explain: 'listing folders and files' },
  T1082: { short: 'Checked the system', explain: 'collecting system information' },
  T1560: { short: 'Packed up data', explain: 'compressing data into an archive before stealing it' },
  T1005: { short: 'Collected data', explain: 'gathering files from the machine' },
  T1048: { short: 'Sent data out', explain: 'exfiltration: copying data to an outside server' },
  T1041: { short: 'Sent data out', explain: 'exfiltration over the attacker’s control channel' },
  T1567: { short: 'Uploaded data to the web', explain: 'exfiltration to a cloud or web service' },
  T1486: { short: 'Encrypted files', explain: 'ransomware: locking files so they cannot be used' },
  T1490: { short: 'Deleted backups', explain: 'removing recovery options before an attack' },
  T1485: { short: 'Destroyed data', explain: 'deleting data to cause damage' },
  T1547: { short: 'Set to auto-start', explain: 'persistence: making malware run at every logon' },
  T1543: { short: 'Installed a service', explain: 'persistence through a system service' },
  T1053: { short: 'Scheduled a task', explain: 'persistence or execution through scheduled tasks' },
  T1136: { short: 'Created an account', explain: 'adding a new account to keep access' },
  T1098: { short: 'Changed an account', explain: 'modifying permissions or credentials of an account' },
  T1068: { short: 'Gained admin rights', explain: 'privilege escalation through a vulnerability' },
  T1548: { short: 'Gained admin rights', explain: 'bypassing controls to get higher privileges' },
  T1003: { short: 'Dumped passwords', explain: 'reading stored credentials from memory or disk' },
  T1558: { short: 'Stole login tickets', explain: 'abusing Kerberos tickets' },
  T1071: { short: 'Called home', explain: 'command and control: talking to the attacker’s server' },
  T1105: { short: 'Downloaded tools', explain: 'bringing attack tools onto the machine' },
  T1219: { short: 'Remote-control tool', explain: 'using remote access software' },
  T1562: { short: 'Turned off defences', explain: 'disabling security tools or logging' },
  T1070: { short: 'Wiped traces', explain: 'clearing logs or deleting evidence' },
  T1027: { short: 'Hid code', explain: 'obfuscating scripts or files' },
  T1055: { short: 'Hid inside a process', explain: 'process injection' },
  T1595: { short: 'Scanned from outside', explain: 'active scanning before the attack' },
}

/** Tactic -> plain outcome used for incident titles and fallbacks. */
const TACTIC_OUTCOME: Record<string, string> = {
  Reconnaissance: 'scouting',
  'Resource Development': 'preparing tools',
  'Initial Access': 'got in',
  Execution: 'ran commands',
  Persistence: 'stayed on the machine',
  'Privilege Escalation': 'gained admin rights',
  Stealth: 'hid its tracks',
  'Defense Impairment': 'turned off defences',
  'Credential Access': 'stole passwords',
  Discovery: 'explored the network',
  'Lateral Movement': 'spread to other machines',
  Collection: 'gathered data',
  'Command and Control': 'called home',
  Exfiltration: 'data sent out',
  Impact: 'damage done',
}

const TACTIC_EXPLAIN: Record<string, string> = {
  Reconnaissance: 'gathering information before the attack',
  'Resource Development': 'setting up infrastructure or tools',
  'Initial Access': 'the first way in',
  Execution: 'running the attacker’s code',
  Persistence: 'keeping access after a reboot or logoff',
  'Privilege Escalation': 'getting higher permissions',
  Stealth: 'avoiding detection',
  'Defense Impairment': 'weakening security controls',
  'Credential Access': 'stealing passwords or keys',
  Discovery: 'learning about the environment',
  'Lateral Movement': 'moving between machines',
  Collection: 'gathering data of interest',
  'Command and Control': 'remote control of compromised machines',
  Exfiltration: 'stealing data out of the network',
  Impact: 'disrupting or destroying systems or data',
}

function parent(id: string): string {
  return id.split('.')[0].toUpperCase()
}

/** "Password Guessing" -> "Password guessing", but keeps product-style words ("PowerShell", "RDP"). */
function sentenceCase(s: string): string {
  const words = s.trim().split(/\s+/)
  return words
    .map((w, i) => {
      if (i === 0) return w.charAt(0).toUpperCase() + w.slice(1)
      return /^[A-Z][a-z]+$/.test(w) ? w.toLowerCase() : w
    })
    .join(' ')
}

function lowerFirst(s: string): string {
  return /^[A-Z][a-z]/.test(s) ? s.charAt(0).toLowerCase() + s.slice(1) : s
}

function joinList(items: string[]): string {
  if (items.length <= 1) return items.join('')
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}

/** Sub-techniques whose plain name differs from the parent's. */
const BY_SUB: Record<string, Plain> = {
  'T1110.001': { short: 'Password guessing', explain: 'trying many passwords on one account' },
  'T1110.003': { short: 'Password spraying', explain: 'trying one common password on many accounts' },
  'T1110.004': { short: 'Credential stuffing', explain: 'trying leaked username/password pairs' },
  'T1059.001': { short: 'Ran PowerShell', explain: 'running PowerShell commands or scripts' },
  'T1021.001': { short: 'Remote desktop (RDP)', explain: 'logging in to another machine over RDP' },
  'T1021.002': { short: 'Moved over file shares', explain: 'using SMB admin shares to reach another machine' },
}

export function stepPlain(s: Step): Plain {
  const sub = s.sub_technique_id ? BY_SUB[s.sub_technique_id.toUpperCase()] : undefined
  if (sub) return sub
  const p = BY_TECHNIQUE[parent(s.technique_id)]
  if (p) return p
  const name = s.technique_name ? sentenceCase(s.technique_name) : null
  return {
    short: name ?? sentenceCase(TACTIC_OUTCOME[s.tactic] ?? s.tactic),
    explain: TACTIC_EXPLAIN[s.tactic] ?? s.tactic,
  }
}

/** Tooltip text: "ATT&CK T1110.001 = Password Guessing: trying many passwords until one works". */
export function techniqueTooltip(s: Step): string {
  const id = s.sub_technique_id ?? s.technique_id
  return `MITRE ATT&CK ${id} = ${s.technique_name ?? id}: ${stepPlain(s).explain}`
}

export function tacticTooltip(tactic: string): string {
  return `ATT&CK tactic "${tactic}": ${TACTIC_EXPLAIN[tactic] ?? 'attacker goal'}`
}

/** Strip "user:", "host:", "ip:" prefixes for display ("host:srv-dc-01" -> "srv-dc-01"). */
export function plainEntities(text: string): string {
  return text.replace(/\b(host|user|ip|domain):/g, '')
}

function finalOutcome(tactics: string[]): string | null {
  const last = [...tactics].sort((a, b) => tacticIndex(b) - tacticIndex(a))[0]
  return last ? (TACTIC_OUTCOME[last] ?? null) : null
}

/** "Password guessing on srv-dc-01 → data sent out" from an index row (no steps available). */
export function summaryTitle(r: IncidentSummary): string {
  const head = sentenceCase(r.entry_summary.split(/\s+(on|against|from|by)\s+/i)[0] || r.entry_summary)
  const where = r.hosts[0]
  const out = finalOutcome(r.tactics)
  const first = head + (where ? ` on ${where}` : '')
  return out && !head.toLowerCase().includes(out) ? `${first} → ${out}` : first
}

/** Same idea from the full incident: first step's plain name + its host → final outcome. */
export function incidentTitle(inc: Incident): string {
  const steps = [...inc.backbone].sort((a, b) => a.step - b.step)
  const first = steps.find((s) => s.step === inc.entry_point.step) ?? steps[0]
  if (!first) return plainEntities(inc.entry_point.summary)
  const head = `${stepPlain(first).short}${first.host ? ` on ${first.host}` : ''}`
  const last = steps[steps.length - 1]
  if (!last || last === first) return head
  return `${head} → ${stepPlain(last).short.toLowerCase()}`
}

export interface PathNode {
  key: string
  steps: Step[]
  label: string
  host: string | null
  tactic: string
}

/** 4–7 big steps: merge consecutive steps with the same plain label + host; compress the middle if still long. */
export function simplePath(inc: Incident, max = 7): { nodes: PathNode[]; hidden: number } {
  const steps = [...inc.backbone].sort((a, b) => a.step - b.step)
  const nodes: PathNode[] = []
  for (const s of steps) {
    const label = stepPlain(s).short
    const prev = nodes[nodes.length - 1]
    if (prev && prev.label === label && prev.host === s.host) prev.steps.push(s)
    else nodes.push({ key: `${s.episode_id}-${s.step}`, steps: [s], label, host: s.host, tactic: s.tactic })
  }
  if (nodes.length <= max) return { nodes, hidden: 0 }
  const keepHead = Math.ceil((max - 1) / 2)
  const keepTail = max - 1 - keepHead
  const hiddenNodes = nodes.slice(keepHead, nodes.length - keepTail)
  return { nodes: [...nodes.slice(0, keepHead), ...nodes.slice(nodes.length - keepTail)], hidden: hiddenNodes.reduce((n, x) => n + x.steps.length, 0) }
}

/** First n sentences of the narrative (plain text). */
export function firstSentences(text: string, n = 4): { text: string; more: boolean } {
  // Split only at ". " + capital letter, so IDs like "T1110.001" and IPs stay intact.
  const parts = text.trim().split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
  return { text: parts.slice(0, n).join(' '), more: parts.length > n }
}

/**
 * Short plain-English story (2–4 sentences) built only from the incident's own fields: steps (plain names, hosts,
 * IPs, account) and reach-next. The full narrative (template or LLM) stays in the Report tab.
 */
export function plainStory(inc: Incident): string {
  const steps = [...inc.backbone].sort((a, b) => a.step - b.step)
  if (steps.length === 0) return plainEntities(inc.entry_point.summary)
  const first = steps.find((s) => s.step === inc.entry_point.step) ?? steps[0]
  const out: string[] = []
  out.push(
    `It started with ${lowerFirst(stepPlain(first).short)}${first.host ? ` on ${first.host}` : ''}${first.src_ip && first.src_ip !== first.host ? ` from ${first.src_ip}` : ''}${first.user ? `, using the account ${first.user}` : ''}.`,
  )
  const rest = steps.filter((s) => s !== first)
  const last = rest[rest.length - 1]
  const middle: string[] = []
  let prevHost = first.host
  for (const s of rest.slice(0, -1)) {
    const phrase = lowerFirst(stepPlain(s).short)
    const item = s.host && s.host !== prevHost ? `${phrase} (${s.host})` : phrase
    if (middle[middle.length - 1] !== item) middle.push(item)
    prevHost = s.host ?? prevHost
  }
  if (middle.length) out.push(`The attacker then ${joinList(middle.slice(0, 5))}${middle.length > 5 ? ' and more' : ''}.`)
  if (last) out.push(`Finally: ${lowerFirst(stepPlain(last).short)}${last.host ? ` on ${last.host}` : ''}${last.dst_ip ? ` to ${last.dst_ip}` : ''}.`)
  const reach = inc.reach_next.filter((r) => !r.touched)
  if (reach.length) {
    const top = reach.find((r) => r.crown_jewel) ?? reach[0]
    out.push(`${reach.length} more machine${reach.length === 1 ? ' is' : 's are'} within reach, including ${top.host}${top.crown_jewel ? ` (${top.crown_jewel})` : ''}.`)
  }
  return out.join(' ')
}
