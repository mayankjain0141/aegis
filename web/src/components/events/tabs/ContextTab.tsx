import type { AegisEvent } from '../../../lib/types'

interface Props { event: AegisEvent }

export function ContextTab({ event }: Props) {
  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1 min-h-0">
      <div className="border border-border rounded p-3 bg-panel">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-3">Session Context</div>
        <div className="grid grid-cols-2 gap-3">
          {[
            ['Agent ID', event.agent_id],
            ['Session ID', event.session_id],
            ['CWD', event.cwd],
            ['Call #', String(event.session_position)],
            ['Phase', `Phase ${event.phase}`],
            ['Tool', event.tool],
          ].map(([label, value]) => (
            <div key={label}>
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">{label}</div>
              <div className="font-mono text-12 text-zinc-300 truncate">{value}</div>
            </div>
          ))}
        </div>
      </div>
      {event.behavioral && (
        <div className="border border-phase2/30 rounded p-3 bg-phase2/5">
          <div className="text-10 font-sans uppercase tracking-wide text-phase2 mb-2">Behavioral State</div>
          <div className="font-mono text-12 text-zinc-400 space-y-1">
            <div>risk_trend: <span className="text-zinc-200">{event.behavioral.risk_trend.toFixed(3)}</span></div>
            <div>baseline_deviation: <span className="text-zinc-200">{event.behavioral.baseline_deviation.toFixed(3)}</span></div>
            <div>recent_denies: <span className={event.behavioral.recent_denies > 0 ? 'text-deny' : 'text-zinc-200'}>{event.behavioral.recent_denies}</span></div>
            <div>retry_after_deny: <span className={event.behavioral.retry_after_deny ? 'text-deny' : 'text-zinc-200'}>{String(event.behavioral.retry_after_deny)}</span></div>
          </div>
        </div>
      )}
    </div>
  )
}
