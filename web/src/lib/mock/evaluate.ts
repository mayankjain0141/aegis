import type { AegisEvent } from '../types'
import { generateDenyEvent, generateAllowEvent, generateEscalateEvent } from './generators'

interface EvaluateResult {
  event: AegisEvent
}

// Pattern-based evaluation matching the real Aegis engine logic
const DENY_PATTERNS = [
  { pattern: /rm\s+-rf\s+\//, rule: 'critical_path_destruction', severity: 'critical' as const },
  { pattern: /rm\s+.*\/(etc|usr|var|bin|sbin|boot)/, rule: 'critical_path_destruction', severity: 'critical' as const },
  { pattern: /cat\s+.*\/(shadow|passwd|sudoers)/, rule: 'credential_access', severity: 'critical' as const },
  { pattern: /curl.*\|\s*(bash|sh|zsh)/, rule: 'remote_code_execution', severity: 'critical' as const },
  { pattern: /wget.*\|\s*(bash|sh)/, rule: 'remote_code_execution', severity: 'critical' as const },
  { pattern: /curl.*-d\s+@/, rule: 'data_exfiltration', severity: 'high' as const },
  { pattern: /cat.*\|.*curl/, rule: 'data_exfiltration', severity: 'high' as const },
  { pattern: /nc\s+-.*-e\s+\/bin/, rule: 'reverse_shell', severity: 'critical' as const },
  { pattern: /bash.*\/dev\/tcp/, rule: 'reverse_shell', severity: 'critical' as const },
  { pattern: /chmod\s+(777|u\+s)/, rule: 'privilege_escalation', severity: 'high' as const },
  { pattern: /dd\s+if=\/dev\/zero/, rule: 'system_control', severity: 'critical' as const },
  { pattern: /mkfs/, rule: 'system_control', severity: 'critical' as const },
  { pattern: /\/etc\/(shadow|passwd|sudoers|ssh)/, rule: 'sensitive_path_access', severity: 'high' as const },
  { pattern: /~\/\.aws\/credentials/, rule: 'credential_access', severity: 'critical' as const },
  { pattern: /~\/\.ssh\/id_rsa/, rule: 'credential_access', severity: 'high' as const },
]

const ESCALATE_PATTERNS = [
  { pattern: /sudo\s+apt|sudo\s+yum|sudo\s+brew/, rule: 'package_install_elevated' },
  { pattern: /pip\s+install\s+(paramiko|pwntools|impacket)/, rule: 'suspicious_package' },
  { pattern: /npm\s+install.*--global/, rule: 'global_package_install' },
  { pattern: /curl.*unknown.*\.sh/, rule: 'remote_script_fetch' },
]

export function evaluate(command: string): EvaluateResult {
  if (!command.trim()) {
    const event = generateAllowEvent()
    event.raw_command = command
    event.normalized_cmd = command
    return { event }
  }

  // Check deny patterns first
  for (const { pattern, rule, severity } of DENY_PATTERNS) {
    if (pattern.test(command)) {
      const event = generateDenyEvent()
      event.raw_command = command
      event.normalized_cmd = command
      event.rule = rule
      event.severity = severity
      event.confidence = 0.85 + Math.random() * 0.14
      // Ensure eval_chain match step matches the rule
      const matchStep = event.eval_chain.find(s => s.result === 'match')
      if (matchStep) matchStep.rule = rule
      event.policy_source.file = `policies/phase1-deny.yaml`
      event.policy_source.condition = `pattern matches: ${pattern.source}`
      return { event }
    }
  }

  // Check escalate patterns
  for (const { pattern, rule } of ESCALATE_PATTERNS) {
    if (pattern.test(command)) {
      const event = generateEscalateEvent()
      event.raw_command = command
      event.normalized_cmd = command
      event.rule = rule
      event.severity = 'medium'
      const matchStep = event.eval_chain.find(s => s.result === 'match')
      if (matchStep) matchStep.rule = rule
      return { event }
    }
  }

  // Default: allow
  const event = generateAllowEvent()
  event.raw_command = command
  event.normalized_cmd = command

  // Use appropriate rule based on command content
  if (/git\s+/.test(command)) event.rule = 'benign_git_ops'
  else if (/npm\s+/.test(command)) event.rule = 'benign_npm_ops'
  else if (/\bcat\b|\bhead\b|\btail\b|\bless\b/.test(command)) event.rule = 'benign_file_read'
  else event.rule = 'allowed_by_default'

  const matchStep = event.eval_chain.find(s => s.result === 'match')
  if (matchStep) matchStep.rule = event.rule

  return { event }
}
