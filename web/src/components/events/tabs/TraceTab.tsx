import type { AegisEvent, Span } from '../../../lib/types'
import { useState } from 'react'

interface Props { event: AegisEvent }

const SPAN_LABELS: Record<string, string> = {
  bloom_check: 'Bloom Filter', allowlist: 'Allowlist', signal_extract: 'Signal Extract',
  rule_eval: 'Rule Eval', behavioral: 'Behavioral Engine', behavioral_compute: 'Behavioral Engine',
  phase2_rules: 'P2 Rules', llm_classify: 'LLM Classifier', llm: 'LLM Classifier',
  phase3_rules: 'P3 Rules', audit_write: 'Audit Write',
}

const PHASE_COLOR: Record<number, string> = { 1: 'bg-phase1', 2: 'bg-phase2', 3: 'bg-phase3' }
const PHASE_TEXT: Record<number, string> = { 1: 'text-phase1', 2: 'text-phase2', 3: 'text-phase3' }

function formatDuration(us: number): string {
  if (us < 1) return `${(us * 1000).toFixed(0)}ns`
  if (us < 1000) return `${us}µs`
  return `${(us / 1000).toFixed(1)}ms`
}

function SpanRow({ span, total }: { span: Span; total: number }) {
  const [open, setOpen] = useState(false)
  const pct = Math.max((span.duration_us / total) * 100, 1)
  const label = SPAN_LABELS[span.name] ?? span.name.replace(/_/g, ' ')

  return (
    <div className="border border-border-faint rounded mb-1 overflow-hidden">
      <div
        className="flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-raised/50"
        onClick={() => setOpen(o => !o)}
      >
        <span className={`font-sans text-10 font-semibold uppercase tracking-wide w-3 ${PHASE_TEXT[span.phase]}`}>
          P{span.phase}
        </span>
        <span className="font-mono text-12 text-zinc-300 w-36 shrink-0">{label}</span>
        <div className="flex-1 h-2 bg-base rounded overflow-hidden">
          <div
            className={`h-full rounded ${PHASE_COLOR[span.phase]}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="font-mono text-11 text-zinc-400 w-14 text-right shrink-0">{formatDuration(span.duration_us)}</span>
        {span.result && (
          <span className={`font-mono text-10 w-10 text-right shrink-0 ${span.result === 'match' ? 'text-deny' : 'text-zinc-600'}`}>
            {span.result}
          </span>
        )}
        <span className="text-zinc-600 text-10 ml-1">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="px-3 pb-3 border-t border-border-faint bg-base/50">
          <div className="grid grid-cols-3 gap-3 mt-2 mb-2">
            <div>
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Start</div>
              <div className="font-mono text-11 text-zinc-400">{formatDuration(span.start_us)}</div>
            </div>
            <div>
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Duration</div>
              <div className="font-mono text-11 text-zinc-400">{formatDuration(span.duration_us)}</div>
            </div>
            <div>
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Phase</div>
              <div className={`font-mono text-11 ${PHASE_TEXT[span.phase]}`}>P{span.phase}</div>
            </div>
          </div>
          {span.result && (
            <div className="mb-2">
              <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-0.5">Result</div>
              <div className={`font-mono text-11 ${span.result === 'match' ? 'text-deny' : 'text-zinc-500'}`}>{span.result}</div>
            </div>
          )}
          {span.metadata && (
            <pre className="font-mono text-10 text-zinc-500 whitespace-pre-wrap bg-panel rounded p-2 mt-1">
              {JSON.stringify(span.metadata, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

export function TraceTab({ event }: Props) {
  const total = event.trace.total_us || event.latency_us || 1
  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1 min-h-0">
      <div className="flex items-center justify-between mb-1">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600">Execution Waterfall</div>
        <span className="font-mono text-10 text-zinc-500">total: {formatDuration(total)}</span>
      </div>
      {event.trace.spans.map((span, i) => (
        <SpanRow key={i} span={span} total={total} />
      ))}
      <div className="mt-2 pt-3 border-t border-border-faint flex items-center gap-2">
        <div className={`w-3 h-3 rounded-full ${event.action === 'deny' ? 'bg-deny' : event.action === 'allow' ? 'bg-allow' : 'bg-escalate'}`} />
        <span className="font-mono text-12 text-zinc-300">Verdict: {event.action.toUpperCase()}</span>
        <span className="font-mono text-10 text-zinc-500 ml-auto">{event.rule}</span>
      </div>
    </div>
  )
}
