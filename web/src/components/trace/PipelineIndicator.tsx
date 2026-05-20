import type { AegisEvent } from '../../lib/types'

interface Props { event: AegisEvent }

const PHASE_COLOR: Record<number, string> = { 1: 'bg-phase1', 2: 'bg-phase2', 3: 'bg-phase3' }
const PHASE_TEXT: Record<number, string> = { 1: 'text-phase1', 2: 'text-phase2', 3: 'text-phase3' }

const SPAN_LABELS: Record<string, string> = {
  bloom_check: 'Bloom Filter',
  allowlist: 'Allowlist',
  signal_extract: 'Signal Extract',
  rule_eval: 'Rule Eval',
  behavioral: 'Behavioral Engine',
  behavioral_compute: 'Behavioral Engine',
  behavioral_check: 'Behavioral Engine',
  sequence_match: 'Sequence Match',
  phase2_rules: 'P2 Rules',
  llm_classify: 'LLM Classifier',
  llm: 'LLM Classifier',
  phase3_rules: 'P3 Rules',
  audit_write: 'Audit Write',
  normalize: 'Normalize',
  eval_chain: 'Eval Chain',
  policy_match: 'Policy Match',
}

export function PipelineIndicator({ event }: Props) {
  const { trace, phase, latency_us, action } = event
  const total = trace.total_us || latency_us || 1

  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="flex items-center justify-between mb-2">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600">Pipeline</div>
        <div className="flex items-center gap-2">
          <span className={`text-10 font-sans font-semibold ${PHASE_TEXT[phase]}`}>P{phase}</span>
          <span className="font-mono text-10 text-zinc-500">{latency_us}µs total</span>
        </div>
      </div>

      {phase === 1 ? (
        <div className="flex items-center gap-1 overflow-x-auto">
          {trace.spans.map((span, i) => (
            <div key={i} className="flex items-center gap-1 shrink-0">
              <div className="flex flex-col items-center">
                <div className={`w-2 h-2 rounded-full ${PHASE_COLOR[span.phase]}`} />
                <span className="font-mono text-10 text-zinc-600 mt-0.5 max-w-16 text-center truncate">{SPAN_LABELS[span.name] ?? span.name.replace(/_/g, ' ')}</span>
              </div>
              {i < trace.spans.length - 1 && <div className="w-4 h-px bg-border-faint shrink-0" />}
            </div>
          ))}
          <div className="w-4 h-px bg-border-faint shrink-0" />
          <div className="flex flex-col items-center shrink-0">
            <div className={`w-2 h-2 rounded-full ${action === 'deny' ? 'bg-deny' : action === 'allow' ? 'bg-allow' : 'bg-escalate'}`} />
            <span className="font-mono text-10 text-zinc-600 mt-0.5">verdict</span>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          {trace.spans.map((span, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="font-mono text-10 text-zinc-600 w-20 truncate shrink-0">{SPAN_LABELS[span.name] ?? span.name.replace(/_/g, ' ')}</span>
              <div className="flex-1 h-3 bg-base rounded overflow-hidden">
                <div
                  className={`h-full rounded ${PHASE_COLOR[span.phase]}`}
                  style={{ width: `${Math.max((span.duration_us / total) * 100, 2)}%` }}
                />
              </div>
              <span className="font-mono text-10 text-zinc-600 w-12 text-right shrink-0">{span.duration_us}µs</span>
            </div>
          ))}
          <div className="flex items-center gap-2 mt-1 pt-1 border-t border-border-faint">
            <span className="font-mono text-10 text-zinc-500 w-20 shrink-0">verdict</span>
            <div className={`w-3 h-3 rounded-full ${action === 'deny' ? 'bg-deny' : action === 'allow' ? 'bg-allow' : 'bg-escalate'}`} />
          </div>
        </div>
      )}
    </div>
  )
}
