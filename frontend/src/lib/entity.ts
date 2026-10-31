// Display helpers for entity strings. Display only: labels are shown exactly as the API sends them
// (never upper-cased here), so IPs like "10.10.20.15" and devnames like "fgt60ftk-sim" stay as-is.

/**
 * Firewall / security-device heuristic for FortiGate data (DEVELOPMENT.md §15.9: `host` = devname).
 * The contract has no "firewall" node type, so this is a name match on the entity value.
 */
const FIREWALL_RE = /^(fgt|fortigate|fortinet|firewall|fw[-_0-9])/i

export function entityValue(idOrValue: string): string {
  const i = idOrValue.indexOf(':')
  return i > 0 && /^(host|user|ip|domain)$/i.test(idOrValue.slice(0, i)) ? idOrValue.slice(i + 1) : idOrValue
}

export function isFirewall(idOrValue: string | null | undefined): boolean {
  return !!idOrValue && FIREWALL_RE.test(entityValue(idOrValue))
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

export function isIp(value: string | null | undefined): boolean {
  return !!value && (IPV4_RE.test(value) || (value.includes(':') && /^[0-9a-f:]+$/i.test(value)))
}
