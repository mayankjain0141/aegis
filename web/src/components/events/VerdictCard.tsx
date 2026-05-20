import { motion } from 'framer-motion'
import type { AegisEvent } from '../../lib/types'

const VERDICT_LABEL = { deny: 'DENIED', allow: 'ALLOWED', escalate: 'ESCALATED' }
const VERDICT_STYLE = {
  deny: 'bg-deny/10 border-deny/30 text-deny',
  allow: 'bg-allow/10 border-allow/30 text-allow',
  escalate: 'bg-escalate/10 border-escalate/30 text-escalate',
}
const SEVERITY_COLOR = {
  critical: 'text-deny', high: 'text-deny', medium: 'text-escalate',
  low: 'text-zinc-400', info: 'text-zinc-500',
}

interface Props { event: AegisEvent }

export function VerdictCard({ event }: Props) {
  return (
    <motion.div
      initial={{ scale: 0.98, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.15 }}
      className={`border rounded p-3 ${VERDICT_STYLE[event.action]}`}
    >
      <div className="text-16 font-sans font-semibold tracking-wide mb-1">
        {VERDICT_LABEL[event.action]}
      </div>
      <div className="font-mono text-12 text-zinc-300 mb-1">{event.rule}</div>
      <div className="flex items-center gap-3 mt-2">
        <div>
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-500 mb-0.5">Confidence</div>
          <div className="font-mono text-13 text-zinc-200">{Math.round(event.confidence * 100)}%</div>
        </div>
        {event.severity && (
          <div>
            <div className="text-10 font-sans uppercase tracking-wide text-zinc-500 mb-0.5">Severity</div>
            <div className={`font-mono text-13 uppercase ${SEVERITY_COLOR[event.severity]}`}>{event.severity}</div>
          </div>
        )}
      </div>
    </motion.div>
  )
}
