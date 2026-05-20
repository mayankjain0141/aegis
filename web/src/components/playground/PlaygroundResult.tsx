import type { AegisEvent } from '../../lib/types'
import { VerdictCard } from '../events/VerdictCard'
import { SignalBreakdown } from '../signals/SignalBreakdown'
import { EvalChain } from '../policy/EvalChain'
import { PipelineIndicator } from '../trace/PipelineIndicator'

interface Props { event: AegisEvent }

export function PlaygroundResult({ event }: Props) {
  return (
    <div className="flex flex-col gap-3 mt-4">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600">Result</div>
      <VerdictCard event={event} />
      <SignalBreakdown event={event} />
      <PipelineIndicator event={event} />
      <EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />
    </div>
  )
}
