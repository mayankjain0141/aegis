import type { SignalBundle, Action, AnalyzedPath, AnalyzedHost } from '../types'

const CRITICAL_PATHS = ['/etc/shadow', '/etc/passwd', '/etc/sudoers', '/boot', '/dev/sda']
const SENSITIVE_PATHS = ['/etc', '~/.ssh', '~/.aws', '/.aws', '/root', '/proc', '/sys']

function rand(min: number, max: number): number {
  return Math.random() * (max - min) + min
}

function clamp(val: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, val))
}

function extractPaths(command: string): string[] {
  const matches = command.match(/(?:\/[^\s|;&<>'"]+|~\/[^\s|;&<>'"]+)/g)
  return matches ?? []
}

function extractHosts(command: string): string[] {
  const matches = command.match(/https?:\/\/([^\s/'"]+)/g)
  return (matches ?? []).map(u => {
    try {
      return new URL(u).hostname
    } catch {
      return u
    }
  })
}

function isMaliciousHost(host: string): boolean {
  const malicious = ['evil.com', 'attacker.com', 'exfil.attacker.com', 'malware.com']
  return malicious.some(m => host.includes(m))
}

function analyzePaths(command: string, baseRisk: number): SignalBundle['path'] {
  const rawPaths = extractPaths(command)
  const paths: AnalyzedPath[] = rawPaths.map(p => {
    const is_critical = CRITICAL_PATHS.some(cp => p.includes(cp))
    const is_sensitive = SENSITIVE_PATHS.some(sp => p.startsWith(sp) || p.includes(sp))
    const in_project = !p.startsWith('/') || p.startsWith('/home') || p.startsWith('/tmp')
    const risk_score = is_critical
      ? clamp(rand(0.7, 0.95), 0, 1)
      : is_sensitive
      ? clamp(rand(0.4, 0.7), 0, 1)
      : clamp(baseRisk * rand(0.5, 1.0), 0, 1)
    return { path: p, is_critical, is_sensitive, in_project, risk_score }
  })

  const has_critical = paths.some(p => p.is_critical)
  const has_sensitive = paths.some(p => p.is_sensitive)
  const all_in_project = paths.length > 0 && paths.every(p => p.in_project)
  const max_risk = paths.reduce((acc, p) => Math.max(acc, p.risk_score), baseRisk * rand(0.1, 0.4))

  return { paths, has_critical, has_sensitive, all_in_project, max_risk }
}

function analyzeNetwork(command: string, baseRisk: number): SignalBundle['network'] {
  const hostnames = extractHosts(command)
  const has_pipe_to_net = /\|\s*(?:bash|sh|curl|wget)/.test(command)
  const has_data_flag = /-d\s+@/.test(command) || has_pipe_to_net

  const hosts: AnalyzedHost[] = hostnames.map(h => {
    const is_external = !h.startsWith('192.') && !h.startsWith('10.') && !h.startsWith('localhost')
    const is_known_malicious = isMaliciousHost(h)
    const risk_score = is_known_malicious
      ? clamp(rand(0.75, 0.95), 0, 1)
      : is_external
      ? clamp(rand(0.3, 0.6), 0, 1)
      : clamp(rand(0.05, 0.2), 0, 1)
    return { host: h, is_external, is_known_malicious, risk_score }
  })

  const score =
    hosts.length === 0
      ? clamp(baseRisk * rand(0.05, 0.3), 0, 1)
      : clamp(
          hosts.reduce((acc, h) => Math.max(acc, h.risk_score), 0) *
            (has_data_flag ? 1.3 : 1.0),
          0,
          1,
        )

  return { hosts, has_data_flag, score }
}

function analyzeDLP(command: string, baseRisk: number): SignalBundle['dlp'] {
  const credPatterns = [
    { pattern: '/etc/shadow', desc: 'shadow_file' },
    { pattern: '/etc/passwd', desc: 'passwd_file' },
    { pattern: '~/.aws/credentials', desc: 'aws_credentials' },
    { pattern: '~/.ssh', desc: 'ssh_key' },
    { pattern: 'AKIA', desc: 'aws_access_key' },
  ]

  const hits = credPatterns
    .filter(p => command.includes(p.pattern))
    .map(p => ({
      pattern: p.desc,
      matched: p.pattern,
      is_test_data: false,
    }))

  const has_hit = hits.length > 0
  const score = has_hit
    ? clamp(rand(0.6, 0.9), 0, 1)
    : clamp(baseRisk * rand(0.05, 0.25), 0, 1)

  return { hits, has_hit, all_test: false, score }
}

function analyzeEvasion(command: string, baseRisk: number): SignalBundle['evasion'] {
  const encoding =
    /base64|xxd|od\s+-c|eval\s*\(/.test(command) || /\\x[0-9a-f]{2}/.test(command)
  const recursion = (command.match(/-r[f]?\s/g) ?? []).length

  const score = encoding
    ? clamp(rand(0.5, 0.85), 0, 1)
    : recursion > 1
    ? clamp(rand(0.3, 0.6), 0, 1)
    : clamp(baseRisk * rand(0.02, 0.2), 0, 1)

  return { encoding, recursion, score }
}

function extractVerbs(command: string): string[] {
  const tokens = command.trim().split(/\s+/)
  const verbs: string[] = []
  for (const tok of tokens) {
    // pick up program names (no flags)
    if (!tok.startsWith('-') && /^[a-z0-9_./~]+$/.test(tok)) {
      verbs.push(tok.split('/').pop() ?? tok)
    }
  }
  return [...new Set(verbs)].slice(0, 5)
}

function extractWrappers(command: string): string[] {
  const wrappers: string[] = []
  if (/\bsudo\b/.test(command)) wrappers.push('sudo')
  if (/\benv\b/.test(command)) wrappers.push('env')
  if (/\bnohup\b/.test(command)) wrappers.push('nohup')
  if (/\bxargs\b/.test(command)) wrappers.push('xargs')
  return wrappers
}

export function generateSignals(action: Action, command: string): SignalBundle {
  // Base risk determines the "floor" for signal generation
  const baseRisk =
    action === 'deny' ? rand(0.55, 0.9) : action === 'escalate' ? rand(0.3, 0.65) : rand(0.02, 0.3)

  const isDangerousVerb =
    /\b(rm|mkfs|dd|chmod|chown|kill|pkill|sudo)\b/.test(command)
  const hasPipeToNet = /\|\s*(?:bash|sh|curl|wget)/.test(command)
  const hasSocket = /\b(nc|netcat|ncat)\b.*\b(-e|--exec)\b/.test(command)
  const hasReverseShell = /\/dev\/tcp\b/.test(command)

  let toolScore: number
  let toolCategory: string

  if (action === 'deny') {
    toolCategory = isDangerousVerb
      ? 'shell_exec'
      : hasPipeToNet || hasSocket || hasReverseShell
      ? 'network_tool'
      : 'shell_exec'
    toolScore = clamp(rand(0.6, 0.95), 0, 1)
  } else if (action === 'escalate') {
    toolCategory = 'shell_exec'
    toolScore = clamp(rand(0.3, 0.65), 0, 1)
  } else {
    toolCategory = /^(git|npm|cargo|go|python|docker|kubectl)\b/.test(command)
      ? 'dev_tool'
      : 'shell_exec'
    toolScore = clamp(rand(0.02, 0.35), 0, 1)
  }

  const dangerVerbs = ['rm', 'mkfs', 'dd', 'chmod', 'chown', 'bash', 'sh', 'curl', 'wget', 'nc']
  const presentDangerVerbs = dangerVerbs.filter(v => new RegExp(`\\b${v}\\b`).test(command))

  let maxDanger: number
  if (action === 'deny') {
    maxDanger = clamp(rand(0.65, 0.99), 0, 1)
  } else if (action === 'escalate') {
    maxDanger = clamp(rand(0.35, 0.65), 0, 1)
  } else {
    maxDanger = clamp(
      presentDangerVerbs.length > 0 ? rand(0.15, 0.38) : rand(0.01, 0.2),
      0,
      1,
    )
  }

  const pathSignals = analyzePaths(command, baseRisk)
  const networkSignals = analyzeNetwork(command, baseRisk)
  const dlpSignals = analyzeDLP(command, baseRisk)
  const evasionSignals = analyzeEvasion(command, baseRisk)

  const mlScore =
    action === 'deny'
      ? clamp(rand(0.55, 0.95), 0, 1)
      : action === 'escalate'
      ? clamp(rand(0.3, 0.65), 0, 1)
      : clamp(rand(0.02, 0.35), 0, 1)

  return {
    tool_class: { category: toolCategory, score: toolScore },
    command: {
      verbs: extractVerbs(command),
      max_danger: maxDanger,
      wrappers: extractWrappers(command),
    },
    path: pathSignals,
    network: networkSignals,
    dlp: dlpSignals,
    evasion: evasionSignals,
    ml_score: mlScore,
  }
}
