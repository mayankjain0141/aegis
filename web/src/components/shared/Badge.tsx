import type { Action } from '../../lib/types'

const LABELS: Record<Action, string> = { deny: 'DENY', allow: 'ALLOW', escalate: 'ESC' }
const COLORS: Record<Action, string> = {
  deny: 'text-deny bg-deny/10 border-deny/30',
  allow: 'text-allow bg-allow/10 border-allow/30',
  escalate: 'text-escalate bg-escalate/10 border-escalate/30',
}

interface BadgeProps { action: Action }

export function Badge({ action }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-10 font-mono font-medium border ${COLORS[action]}`}>
      {LABELS[action]}
    </span>
  )
}
