import type { EvalStep, Action } from '../types'

const RULES = [
  'critical_path_destruction',
  'system_control',
  'raw_socket_open',
  'remote_code_execution',
  'data_exfiltration',
  'credential_access',
  'privilege_escalation',
  'reverse_shell',
  'supply_chain_attack',
  'benign_git_ops',
  'benign_npm_ops',
  'benign_file_read',
  'sensitive_path_access',
  'network_data_post',
]

const RULE_CONDITIONS: Record<string, string> = {
  critical_path_destruction: 'path.is_critical AND command.verb == "rm" AND command.flags.contains("-rf")',
  system_control: 'tool_class.category == "shell_exec" AND command.max_danger > 0.8',
  raw_socket_open: 'network.has_raw_socket AND NOT network.is_known_host',
  remote_code_execution: 'network.score > 0.7 AND command.wrappers.contains("bash")',
  data_exfiltration: 'dlp.has_hit AND network.has_data_flag AND network.is_external',
  credential_access: 'path.is_sensitive AND dlp.pattern.matches("credential")',
  privilege_escalation: 'command.wrappers.contains("sudo") AND command.max_danger > 0.5',
  reverse_shell: 'network.has_raw_socket AND command.verb == "bash" AND network.has_data_flag',
  supply_chain_attack: 'network.score > 0.5 AND command.verb.in(["pip","npm","curl"]) AND network.is_external',
  benign_git_ops: 'tool_class.category == "dev_tool" AND command.verb == "git" AND ml_score < 0.3',
  benign_npm_ops: 'tool_class.category == "dev_tool" AND command.verb == "npm" AND ml_score < 0.3',
  benign_file_read: 'command.verb.in(["cat","head","tail"]) AND NOT path.is_sensitive AND ml_score < 0.2',
  sensitive_path_access: 'path.is_sensitive AND NOT dlp.has_hit AND ml_score < 0.6',
  network_data_post: 'network.has_data_flag AND network.score > 0.4',
}

function pickSkipRules(matchedRule: string, count: number): string[] {
  const others = RULES.filter(r => r !== matchedRule)
  // shuffle
  const shuffled = [...others].sort(() => Math.random() - 0.5)
  return shuffled.slice(0, count)
}

export function generateEvalChain(matchedRule: string, action: Action): EvalStep[] {
  // total steps between 5 and 15
  const total = Math.floor(Math.random() * 11) + 5
  const skipCount = total - 1

  const skipRules = pickSkipRules(matchedRule, Math.min(skipCount, RULES.length - 1))

  // fill up to total - 1 with potentially repeated or shortened list
  const allSkipRules: string[] = []
  while (allSkipRules.length < skipCount) {
    const needed = skipCount - allSkipRules.length
    const batch = [...skipRules].sort(() => Math.random() - 0.5).slice(0, needed)
    allSkipRules.push(...batch)
  }

  // Determine insertion index for the match step
  const matchIndex = Math.floor(Math.random() * total)

  const steps: EvalStep[] = []
  let skipIdx = 0
  let priorityBase = 10

  for (let i = 0; i < total; i++) {
    const priority = priorityBase
    priorityBase += Math.floor(Math.random() * 15) + 5

    if (i === matchIndex) {
      steps.push({
        rule: matchedRule,
        priority,
        action,
        result: 'match',
        condition: RULE_CONDITIONS[matchedRule] ?? `signals.composite > 0.5 AND rule == "${matchedRule}"`,
        latency_us: Math.floor(Math.random() * 200) + 10,
      })
    } else {
      const rule = allSkipRules[skipIdx++] ?? RULES[0]
      steps.push({
        rule,
        priority,
        action: (['allow', 'deny', 'escalate'] as Action[])[Math.floor(Math.random() * 3)],
        result: 'skip',
        latency_us: Math.floor(Math.random() * 50) + 2,
      })
    }
  }

  // Sort by ascending priority
  steps.sort((a, b) => a.priority - b.priority)

  return steps
}
