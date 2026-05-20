import type { AegisEvent } from '../../../lib/types'
import { CommandBlock } from '../CommandBlock'
import { VerdictCard } from '../VerdictCard'
import { BehavioralCard } from '../BehavioralCard'
import { LLMCard } from '../LLMCard'
import { SignalBreakdown } from '../../signals/SignalBreakdown'
import { PipelineIndicator } from '../../trace/PipelineIndicator'
import { EvalChain } from '../../policy/EvalChain'
import { PolicySource } from '../../policy/PolicySource'
import { RemediationPanel } from '../RemediationPanel'
import { RiskAnalysis } from './RiskAnalysis'

interface Props { event: AegisEvent }

export function SummaryTab({ event }: Props) {
  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1">
      <CommandBlock event={event} />
      <div className="flex gap-3">
        <div className="w-56 shrink-0"><VerdictCard event={event} /></div>
        <div className="flex-1"><PipelineIndicator event={event} /></div>
      </div>
      <SignalBreakdown event={event} />
      <BehavioralCard event={event} />
      <LLMCard event={event} />
      <RiskAnalysis event={event} />
      <EvalChain evalChain={event.eval_chain} matchedRule={event.rule} />
      <PolicySource
        file={event.policy_source.file}
        line={event.policy_source.line}
        snippet={event.policy_source.snippet}
        condition={event.policy_source.condition}
      />
      <RemediationPanel event={event} />
    </div>
  )
}
