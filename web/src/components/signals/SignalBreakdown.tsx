import type { AegisEvent } from '../../lib/types'
import { SignalBar } from './SignalBar'

interface Props { event: AegisEvent }

export function SignalBreakdown({ event }: Props) {
  const { signals } = event

  const bars = [
    { name: 'Tool', score: signals.tool_class.score },
    { name: 'Command', score: signals.command.max_danger },
    { name: 'Path', score: signals.path.max_risk },
    { name: 'Network', score: signals.network.score },
    { name: 'DLP', score: signals.dlp.score },
    { name: 'Evasion', score: signals.evasion.score },
  ]

  const maxScore = Math.max(...bars.map(b => b.score))
  const triggeredName = maxScore > 0.6 ? bars.find(b => b.score === maxScore)?.name : undefined

  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Signal Breakdown</div>
      <div className="flex flex-col gap-0.5">
        {bars.map((bar, index) => (
          <SignalBar
            key={bar.name}
            name={bar.name}
            score={bar.score}
            isTriggered={bar.name === triggeredName}
            index={index}
          />
        ))}
      </div>
    </div>
  )
}
