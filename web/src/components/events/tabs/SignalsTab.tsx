import type { AegisEvent } from '../../../lib/types'
import { RadarChart } from '../../signals/RadarChart'
import { SignalBreakdown } from '../../signals/SignalBreakdown'

interface Props { event: AegisEvent }

export function SignalsTab({ event }: Props) {
  const { signals } = event
  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1 min-h-0">
      <div className="flex gap-4 items-start">
        <div className="flex flex-col items-center gap-1">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-1">Signal Radar</div>
          <RadarChart signals={signals} size={180} />
          <span className="font-mono text-10 text-zinc-600">ml_score: {signals.ml_score.toFixed(3)}</span>
        </div>
        <div className="flex-1">
          <SignalBreakdown event={event} />
        </div>
      </div>

      {/* Path details */}
      {signals.path.paths.length > 0 && (
        <div className="border border-border rounded p-3 bg-panel">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Path Analysis</div>
          {signals.path.paths.map((p, i) => (
            <div key={i} className="flex items-center gap-2 py-1 border-b border-border-faint last:border-0">
              <span className="font-mono text-12 text-zinc-300 flex-1">{p.path}</span>
              {p.is_critical && <span className="text-10 font-sans text-deny border border-deny/30 rounded px-1">CRITICAL</span>}
              {p.is_sensitive && <span className="text-10 font-sans text-escalate border border-escalate/30 rounded px-1">SENSITIVE</span>}
              <span className="font-mono text-10 text-zinc-500">{p.risk_score.toFixed(2)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Network details */}
      {signals.network.hosts.length > 0 && (
        <div className="border border-border rounded p-3 bg-panel">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Network Analysis</div>
          {signals.network.hosts.map((h, i) => (
            <div key={i} className="flex items-center gap-2 py-1 border-b border-border-faint last:border-0">
              <span className="font-mono text-12 text-zinc-300 flex-1">{h.host}</span>
              {h.is_external && <span className="text-10 font-sans text-escalate border border-escalate/30 rounded px-1">EXTERNAL</span>}
              {h.is_known_malicious && <span className="text-10 font-sans text-deny border border-deny/30 rounded px-1">MALICIOUS</span>}
              <span className="font-mono text-10 text-zinc-500">{h.risk_score.toFixed(2)}</span>
            </div>
          ))}
        </div>
      )}

      {/* DLP hits */}
      {signals.dlp.hits.length > 0 && (
        <div className="border border-border rounded p-3 bg-panel">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">DLP Matches</div>
          {signals.dlp.hits.map((hit, i) => (
            <div key={i} className="flex items-center gap-2 py-1 border-b border-border-faint last:border-0 font-mono text-12">
              <span className="text-zinc-600">{hit.pattern}</span>
              <span className="text-zinc-300 flex-1">{hit.matched}</span>
              {hit.is_test_data && <span className="text-10 text-zinc-500">test data</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
