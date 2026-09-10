export const MAX_BATCH_TARGETS = 20

// Full-scan batches run an entire Standard/Deep scan (port scan, directory
// enum, subdomain enum, email gather, etc.) per target rather than one
// lightweight module check — a lower cap keeps that aggregate workload
// reasonable. Kept separate from MAX_BATCH_TARGETS so the older
// single-module batch (SingleModuleView) is unaffected.
export const MAX_FULL_SCAN_BATCH_TARGETS = 10

export function classifyPrivateIp(target) {
  const m = target.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return null
  const octets = m.slice(1).map(Number)
  if (octets.some((o) => o > 255)) return null
  const [a, b] = octets
  if (a === 127) return 'loopback address'
  if (a === 169 && b === 254) return 'link-local address'
  if (a === 10) return 'private/internal address'
  if (a === 172 && b >= 16 && b <= 31) return 'private/internal address'
  if (a === 192 && b === 168) return 'private/internal address'
  if (a === 100 && b >= 64 && b <= 127) return 'private/internal address'
  return null
}

export function classifyMalformedIp(target) {
  const segments = target.trim().split('.')
  if (segments.length < 2 || !segments.every((s) => /^\d+$/.test(s))) return null
  if (segments.length !== 4) {
    return `not a valid IP address — expected 4 dot-separated numbers, got ${segments.length}`
  }
  const badOctet = segments.find((s) => Number(s) > 255)
  if (badOctet) {
    return `not a valid IP address — '${badOctet}' is out of range (must be 0-255)`
  }
  return null
}

export function looksLikeIp(target) {
  const m = target.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!m) return false
  return m.slice(1).map(Number).every((o) => o <= 255)
}

export function looksLikeIpv6(target) {
  return target.trim().includes(':')
}

export const RANGE_SHORT_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})$/
export const RANGE_FULL_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*-\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/

const isValidOctet = (n) => Number.isInteger(n) && n >= 0 && n <= 255

function ipToInt(ip) {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((p) => !isValidOctet(p))) return null
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.')
}

export function expandIpRange(raw, maxTargets = MAX_BATCH_TARGETS) {
  const t = raw.trim()

  let m = t.match(RANGE_SHORT_RE)
  if (m) {
    const [, prefix, startS, endS] = m
    const start = parseInt(startS, 10)
    const end = parseInt(endS, 10)
    const prefixOctets = prefix.split('.').map(Number)
    if (prefixOctets.some((p) => !isValidOctet(p)) || !isValidOctet(start) || !isValidOctet(end)) {
      throw new Error(`'${t}' is not a valid IP range.`)
    }
    if (start > end) {
      throw new Error(`'${t}' is backwards — the start of a range must come before the end.`)
    }
    const count = end - start + 1
    if (count > maxTargets) {
      throw new Error(`'${t}' covers ${count} addresses (${prefix}.${start}–${prefix}.${end}) — maximum is ${maxTargets} per batch check.`)
    }
    const out = []
    for (let i = start; i <= end; i++) out.push(`${prefix}.${i}`)
    return out
  }

  m = t.match(RANGE_FULL_RE)
  if (m) {
    const [, startIpS, endIpS] = m
    const startInt = ipToInt(startIpS)
    const endInt = ipToInt(endIpS)
    if (startInt === null || endInt === null) {
      throw new Error(`'${t}' is not a valid IP range.`)
    }
    if (startInt > endInt) {
      throw new Error(`'${t}' is backwards — the start of a range must come before the end.`)
    }
    const count = endInt - startInt + 1
    if (count > maxTargets) {
      throw new Error(`'${t}' covers ${count} addresses (${startIpS}–${endIpS}) — maximum is ${maxTargets} per batch check.`)
    }
    const out = []
    for (let i = startInt; i <= endInt; i++) out.push(intToIp(i))
    return out
  }

  return null
}

export function parseTargetList(raw, maxTargets = MAX_BATCH_TARGETS) {
  const seen = new Set()
  const out = []
  for (const piece of raw.split(',')) {
    const t = piece.trim()
    if (!t) continue

    const expanded = expandIpRange(t, maxTargets)
    const candidates = expanded !== null ? expanded : [t]

    for (const c of candidates) {
      const key = c.toLowerCase()
      if (seen.has(key)) continue
      seen.add(key)
      out.push(c)
    }
  }
  return out
}

export function countRawExpandedTargets(raw, maxTargets = MAX_BATCH_TARGETS) {
  // Deliberately uncapped (Infinity, not maxTargets): expandIpRange() throws
  // once a range's expanded size exceeds the cap it's given, which is the
  // right behavior for parseTargetList() (building the real submit list —
  // it should reject an oversized range outright). But this function feeds
  // the *live* target counter shown while typing — if it used the same cap
  // and let that exception propagate uncaught, a range like "x.x.x.1-11"
  // (11 > the 10 max) would silently reset the live count to 0 instead of
  // showing the true 11, which is exactly backwards: the one case where an
  // accurate live count matters most (so the "too many" message can show)
  // was the one case that broke it. Genuinely invalid ranges (backwards,
  // bad octets) still throw here same as always — only the size cap is
  // skipped for counting purposes.
  let total = 0
  for (const piece of raw.split(',')) {
    const t = piece.trim()
    if (!t) continue
    let expanded
    try {
      expanded = expandIpRange(t, Infinity)
    } catch {
      expanded = null
    }
    total += expanded !== null ? expanded.length : 1
  }
  return total
}
