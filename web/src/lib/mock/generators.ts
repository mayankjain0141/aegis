import { monotonicFactory } from 'ulidx'
import type { AegisEvent, Action, Phase, Severity, Span } from '../types'
import { BENIGN_COMMANDS, DANGEROUS_COMMANDS, ESCALATE_COMMANDS } from './commands'
import { generateSignals } from './signals'
import { generateEvalChain } from './eval-chain'

const ulid = monotonicFactory()

// Session pool: reuse a small set of session IDs so "Same Session" grouping works
const SESSION_POOL = Array.from({ length: 4 }, (_, i) => `sess-pool${i}-${Math.random().toString(36).slice(2, 6)}`)
const sessionCounters: Record<string, number> = {}

const TOOLS = ['Shell', 'Bash', 'Execute', 'RunCommand', 'Terminal']
const AGENT_IDS = ['agent-alpha', 'agent-beta', 'agent-gamma', 'agent-delta']
const CWDS = [
  '/home/user/project',
  '/workspace/app',
  '/opt/service',
  '/tmp/workspace',
  '/Users/dev/repo',
]

const DENY_RULES = [
  'critical_path_destruction',
  'system_control',
  'raw_socket_open',
  'remote_code_execution',
  'data_exfiltration',
  'credential_access',
  'privilege_escalation',
  'reverse_shell',
]

const ALLOW_RULES = ['benign_git_ops', 'benign_npm_ops', 'benign_file_read']

const ESCALATE_RULES = ['supply_chain_attack', 'sensitive_path_access', 'network_data_post']

const POLICY_FILES = [
  'policies/core.rego',
  'policies/network.rego',
  'policies/filesystem.rego',
  'policies/credentials.rego',
]

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function randFloat(min: number, max: number): number {
  return Math.random() * (max - min) + min
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}

function severityFromScore(composite: number): Severity {
  if (composite >= 0.85) return 'critical'
  if (composite >= 0.65) return 'high'
  if (composite >= 0.45) return 'medium'
  if (composite >= 0.25) return 'low'
  return 'info'
}

function generateSpans(totalUs: number, phase: Phase): Span[] {
  const spanNames =
    phase === 1
      ? ['normalize', 'signal_extract', 'eval_chain', 'policy_match']
      : phase === 2
      ? ['normalize', 'signal_extract', 'behavioral_check', 'sequence_match', 'eval_chain', 'policy_match']
      : ['normalize', 'signal_extract', 'behavioral_check', 'llm_classify', 'eval_chain', 'policy_match']

  const weights = spanNames.map(() => Math.random())
  const totalWeight = weights.reduce((a, b) => a + b, 0)

  let cursor = 0
  const spans: Span[] = spanNames.map((name, i) => {
    const duration = Math.round((weights[i] / totalWeight) * totalUs)
    const span: Span = {
      name,
      start_us: cursor,
      duration_us: duration,
      phase,
    }
    cursor += duration
    return span
  })

  return spans
}

function pickSessionId(): string {
  return SESSION_POOL[Math.floor(Math.random() * SESSION_POOL.length)]
}

export function generateEvent(overrides?: Partial<AegisEvent>): AegisEvent {
  // Default to weighted random action
  const roll = Math.random()
  const action: Action = roll < 0.75 ? 'allow' : roll < 0.90 ? 'deny' : 'escalate'
  return _buildEvent(action, overrides)
}

export function generateDenyEvent(overrides?: Partial<AegisEvent>): AegisEvent {
  return _buildEvent('deny', overrides)
}

export function generateAllowEvent(overrides?: Partial<AegisEvent>): AegisEvent {
  return _buildEvent('allow', overrides)
}

export function generateEscalateEvent(overrides?: Partial<AegisEvent>): AegisEvent {
  return _buildEvent('escalate', overrides)
}

function _buildEvent(action: Action, overrides?: Partial<AegisEvent>): AegisEvent {
  const command =
    action === 'deny'
      ? pick(DANGEROUS_COMMANDS)
      : action === 'escalate'
      ? pick(ESCALATE_COMMANDS)
      : pick(BENIGN_COMMANDS)

  const rule =
    action === 'deny'
      ? pick(DENY_RULES)
      : action === 'allow'
      ? pick(ALLOW_RULES)
      : pick(ESCALATE_RULES)

  // Phase probabilities: ~85% p1, ~10% p2, ~5% p3
  const phaseRoll = Math.random()
  const phase: Phase = phaseRoll < 0.85 ? 1 : phaseRoll < 0.95 ? 2 : 3

  // Latency by phase
  const latency_us =
    phase === 1
      ? randInt(10, 50)
      : phase === 2
      ? randInt(200, 800)
      : randInt(100_000, 300_000)

  const composite_score =
    action === 'deny'
      ? randFloat(0.51, 0.99)
      : action === 'escalate'
      ? randFloat(0.3, 0.7)
      : randFloat(0.01, 0.39)

  const severity = severityFromScore(composite_score)
  const confidence =
    action === 'deny'
      ? randFloat(0.7, 0.99)
      : action === 'escalate'
      ? randFloat(0.4, 0.75)
      : randFloat(0.7, 0.99)

  const signals = generateSignals(action, command)
  const eval_chain = generateEvalChain(rule, action)
  const spans = generateSpans(latency_us, phase)

  const policyFile = pick(POLICY_FILES)
  const policyLine = randInt(10, 300)

  const args_json: Record<string, unknown> = { command }

  const session_id = pickSessionId()
  sessionCounters[session_id] = (sessionCounters[session_id] || 0) + 1
  const session_position = sessionCounters[session_id]

  const event: AegisEvent = {
    id: ulid(),
    time: new Date().toISOString(),
    agent_id: pick(AGENT_IDS),
    session_id,
    tool: pick(TOOLS),
    raw_command: command,
    normalized_cmd: command.trim().replace(/\s+/g, ' '),
    args_json,
    cwd: pick(CWDS),
    action,
    rule,
    severity,
    confidence,
    composite_score,
    phase,
    latency_us,
    signals,
    trace: { spans, total_us: latency_us },
    eval_chain,
    policy_source: {
      file: policyFile,
      line: policyLine,
      snippet: `${rule} { input.signals.composite_score > ${composite_score.toFixed(2)} }`,
      condition: `composite_score > ${composite_score.toFixed(2)}`,
    },
    related_event_ids: [],
    session_position,
  }

  // Phase 2: add behavioral context
  if (phase >= 2) {
    event.behavioral = {
      retry_after_deny: Math.random() > 0.7,
      sequence_matches: Math.random() > 0.5 ? [pick(DENY_RULES)] : [],
      baseline_deviation: randFloat(0.1, 2.5),
      risk_trend: randFloat(-0.5, 1.5),
      recent_denies: randInt(0, 5),
    }
  }

  // Phase 3: add LLM context
  if (phase === 3) {
    const LLM_INTENTS_DENY = [
      { intent: 'Credential Exfiltration', reasoning: 'Command pipes sensitive system file to external HTTP endpoint. Pattern consistent with data theft toolkit behavior observed in APT campaigns.' },
      { intent: 'Reverse Shell Establishment', reasoning: 'Bash TCP redirect to remote IP on non-standard port. Classic reverse shell pattern used to establish persistent C2 channel.' },
      { intent: 'Privilege Escalation Attempt', reasoning: 'SUID bit manipulation on shell binary. Attacker-controlled shell with elevated privileges enables full system compromise.' },
      { intent: 'Defense Evasion', reasoning: 'History file manipulation and environment variable unsetting consistent with anti-forensics techniques to cover attack trail.' },
      { intent: 'Persistence Mechanism', reasoning: 'Cron job or startup script modification to maintain access across reboots. Consistent with long-term persistence TTPs.' },
    ]
    const LLM_INTENTS_ESCALATE = [
      { intent: 'Supply Chain Attack', reasoning: 'Remote script fetched and piped directly to shell without inspection. High confidence this is a supply chain compromise vector.' },
      { intent: 'Lateral Movement Preparation', reasoning: 'SSH key enumeration combined with network scanning suggests preparation for lateral movement within the network.' },
      { intent: 'Suspicious Package Installation', reasoning: 'Installing potentially dangerous tooling from external source without integrity verification or sandboxing.' },
    ]
    const LLM_INTENTS_ALLOW = [
      { intent: 'Routine Development Workflow', reasoning: 'Standard build and test lifecycle operation. Tool invocation, argument structure, and working directory are all consistent with benign developer activity.' },
      { intent: 'Version Control Operation', reasoning: 'Git command on tracked repository path with no network destinations or sensitive file access. Consistent with normal source management.' },
      { intent: 'Dependency Management', reasoning: 'Package manager invocation on known registry with expected argument structure. No anomalous flags or output redirection detected.' },
    ]

    const intentPool =
      action === 'deny'
        ? LLM_INTENTS_DENY
        : action === 'escalate'
        ? LLM_INTENTS_ESCALATE
        : LLM_INTENTS_ALLOW

    const chosen = pick(intentPool)

    event.llm = {
      intent: chosen.intent,
      confidence: randFloat(0.75, 0.99),
      reasoning: chosen.reasoning,
      model: 'claude-3-5-haiku-20241022',
      latency_ms: randInt(80, 350),
    }
  }

  return { ...event, ...overrides }
}

export function generateEventStream(count: number): AegisEvent[] {
  const events: AegisEvent[] = []
  let currentTime = Date.now() - count * 2000 // start ~count*2s ago

  for (let i = 0; i < count; i++) {
    // Advance time by 500ms - 3000ms between events
    currentTime += randInt(500, 3000)

    const roll = Math.random()
    const action: Action = roll < 0.75 ? 'allow' : roll < 0.90 ? 'deny' : 'escalate'

    const event = _buildEvent(action, {
      time: new Date(currentTime).toISOString(),
      session_position: i + 1,
    })

    events.push(event)
  }

  return events
}
