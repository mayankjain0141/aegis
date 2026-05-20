interface Props {
  name: string
  score: number
  isTriggered: boolean
  details?: string[]
  index?: number
}

const fillColor = (score: number) => {
  if (score > 0.6) return 'bg-deny'
  if (score >= 0.3) return 'bg-escalate'
  return 'bg-zinc-600'
}

export function SignalBar({ name, score, isTriggered, index = 0 }: Props) {
  return (
    <div className="flex items-center gap-2 py-1">
      <span className="font-sans text-10 uppercase tracking-wide text-zinc-500 w-16 shrink-0">{name}</span>
      <div className="flex-1 h-1.5 bg-panel rounded-full overflow-hidden border border-border-faint">
        <div
          data-fill
          className={`h-full rounded-full transition-all duration-400 ease-out ${fillColor(score)}`}
          style={{ width: `${score * 100}%`, transitionDelay: `${index * 50}ms` }}
        />
      </div>
      <span className="font-mono text-10 text-zinc-400 w-8 text-right">{score.toFixed(2)}</span>
      {isTriggered && (
        <span className="text-10 font-sans uppercase tracking-wide text-deny border border-deny/30 rounded px-1">TRIGGERED</span>
      )}
    </div>
  )
}
