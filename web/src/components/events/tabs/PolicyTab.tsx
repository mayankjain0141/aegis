import type { AegisEvent } from '../../../lib/types'
import { EvalChain } from '../../policy/EvalChain'
import { PolicySource } from '../../policy/PolicySource'

interface Props { event: AegisEvent }

export function PolicyTab({ event }: Props) {
  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1 min-h-0">
      <EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />
      <PolicySource
        file={event.policy_source.file}
        line={event.policy_source.line}
        snippet={event.policy_source.snippet}
        condition={event.policy_source.condition}
      />
      <div className="border border-border rounded p-3 bg-panel">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Related Rules</div>
        <div className="text-13 font-sans text-zinc-600">
          {event.eval_chain.filter(s => s.result === 'skip').length} other rules evaluated and skipped (first-match semantics).
        </div>
      </div>
    </div>
  )
}
