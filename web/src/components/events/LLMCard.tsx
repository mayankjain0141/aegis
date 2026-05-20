import type { AegisEvent } from '../../lib/types'

interface Props { event: AegisEvent }

export function LLMCard({ event }: Props) {
  const l = event.llm
  if (!l) return null

  const confColor = l.confidence > 0.8 ? 'bg-deny' : l.confidence > 0.5 ? 'bg-escalate' : 'bg-phase3'

  return (
    <div className="border border-phase3/30 rounded p-3 bg-phase3/5">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-10 font-sans font-semibold uppercase tracking-wide text-phase3">LLM Classifier</span>
        <span className="text-10 font-sans text-phase3/60 border border-phase3/30 rounded px-1">P3</span>
        <span className="font-mono text-10 text-zinc-600 ml-auto">{l.model}</span>
        <span className="font-mono text-10 text-zinc-500">{l.latency_ms}ms</span>
      </div>

      {/* Intent — the headline finding */}
      <div className="mb-3">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-1">Classified Intent</div>
        <div className="font-sans text-13 font-semibold text-phase3">{l.intent}</div>
      </div>

      {/* Confidence bar */}
      <div className="flex items-center gap-2 mb-3">
        <span className="font-sans text-10 uppercase tracking-wide text-zinc-500 w-20 shrink-0">Confidence</span>
        <div className="flex-1 h-1.5 bg-base rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${confColor}`} style={{ width: `${l.confidence * 100}%` }} />
        </div>
        <span className="font-mono text-10 text-zinc-400 w-8 text-right">{Math.round(l.confidence * 100)}%</span>
      </div>

      {/* Reasoning */}
      {l.reasoning && (
        <div className="pt-2 border-t border-phase3/20">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-1">Reasoning</div>
          <div className="font-sans text-12 text-zinc-400 leading-relaxed">{l.reasoning}</div>
        </div>
      )}
    </div>
  )
}
