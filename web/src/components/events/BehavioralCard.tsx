import type { AegisEvent } from '../../lib/types'

interface Props { event: AegisEvent }

export function BehavioralCard({ event }: Props) {
  const b = event.behavioral
  if (!b) return null

  const trendColor = b.risk_trend > 0.7 ? 'bg-deny' : b.risk_trend > 0.4 ? 'bg-escalate' : 'bg-phase2'
  const devColor = b.baseline_deviation > 0.6 ? 'bg-deny' : b.baseline_deviation > 0.3 ? 'bg-escalate' : 'bg-zinc-600'

  return (
    <div className="border border-phase2/30 rounded p-3 bg-phase2/5">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-10 font-sans font-semibold uppercase tracking-wide text-phase2">Behavioral Engine</span>
        <span className="text-10 font-sans text-phase2/60 border border-phase2/30 rounded px-1">P2</span>
        {b.retry_after_deny && (
          <span className="text-10 font-sans uppercase tracking-wide text-deny border border-deny/30 rounded px-1 ml-auto">RETRY AFTER DENY</span>
        )}
      </div>

      <div className="flex flex-col gap-2">
        {/* Risk trend */}
        <div className="flex items-center gap-2">
          <span className="font-sans text-10 uppercase tracking-wide text-zinc-500 w-28 shrink-0">Risk Trend</span>
          <div className="flex-1 h-1.5 bg-base rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${trendColor}`} style={{ width: `${b.risk_trend * 100}%` }} />
          </div>
          <span className="font-mono text-10 text-zinc-400 w-8 text-right">{b.risk_trend.toFixed(2)}</span>
        </div>

        {/* Baseline deviation */}
        <div className="flex items-center gap-2">
          <span className="font-sans text-10 uppercase tracking-wide text-zinc-500 w-28 shrink-0">Baseline Dev.</span>
          <div className="flex-1 h-1.5 bg-base rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${devColor}`} style={{ width: `${b.baseline_deviation * 100}%` }} />
          </div>
          <span className="font-mono text-10 text-zinc-400 w-8 text-right">{b.baseline_deviation.toFixed(2)}</span>
        </div>

        {/* Stats row */}
        <div className="flex gap-4 mt-1 pt-2 border-t border-phase2/20">
          <div>
            <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Recent Denies</div>
            <div className={`font-mono text-13 ${b.recent_denies > 0 ? 'text-deny' : 'text-zinc-400'}`}>{b.recent_denies}</div>
          </div>
          {b.sequence_matches.length > 0 && (
            <div>
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Sequences Matched</div>
              <div className="font-mono text-12 text-phase2">{b.sequence_matches.join(', ')}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
