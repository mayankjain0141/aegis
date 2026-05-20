import { useState } from 'react'
import type { EvalStep } from '../../lib/types'

interface Props {
  evalChain: EvalStep[]
  matchedRule: string
}

const COLLAPSED_MAX = 3

export function EvalChain({ evalChain, matchedRule: _matchedRule }: Props) {
  const [expanded, setExpanded] = useState(false)

  const matchIdx = evalChain.findIndex(s => s.result === 'match')
  const skipCount = evalChain.filter(s => s.result === 'skip').length

  const visible = expanded
    ? evalChain
    : (() => {
        // Show: 1 before match, match, 1 after match (max 3)
        const start = Math.max(0, matchIdx - 1)
        const end = Math.min(evalChain.length, matchIdx + 2)
        return evalChain.slice(start, end)
      })()

  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="flex items-center justify-between mb-2">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600">Policy Evaluation Chain</div>
        {skipCount > 0 && (
          <span className="text-10 font-mono text-zinc-600">{skipCount} rules skipped</span>
        )}
      </div>
      <div className="flex flex-col gap-1">
        {visible.map((step, i) => (
          <EvalStepRow key={i} step={step} isMatch={step.result === 'match'} />
        ))}
      </div>
      {!expanded && evalChain.length > COLLAPSED_MAX && (
        <button
          onClick={() => setExpanded(true)}
          className="mt-2 text-10 font-sans text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          Show all {evalChain.length} rules →
        </button>
      )}
    </div>
  )
}

function EvalStepRow({ step, isMatch }: { step: EvalStep; isMatch: boolean }) {
  return (
    <div className={`flex items-start gap-2 py-1 px-2 rounded text-12 ${isMatch ? 'bg-deny/10 border border-deny/30' : 'opacity-50'}`}>
      <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${step.action === 'deny' ? 'bg-deny/50' : step.action === 'allow' ? 'bg-allow/50' : 'bg-escalate/50'}`} />
      <span className={`font-mono text-10 mt-0.5 shrink-0 ${isMatch ? 'text-deny' : 'text-zinc-600'}`}>
        {isMatch ? 'MATCH' : 'SKIP'}
      </span>
      <div className="flex-1 min-w-0">
        <div className="font-mono text-12 text-zinc-300 truncate">{step.rule}</div>
        {isMatch && step.condition && (
          <div className="font-mono text-10 text-zinc-500 mt-0.5">{step.condition}</div>
        )}
      </div>
      <span className="font-mono text-10 text-zinc-600 shrink-0">P{step.priority}</span>
      {step.latency_us && (
        <span className="font-mono text-10 text-zinc-600 ml-auto shrink-0">{step.latency_us}µs</span>
      )}
    </div>
  )
}
