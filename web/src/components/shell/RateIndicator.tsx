import { useStreamStore } from '../../stores/stream'

export function RateIndicator() {
  const { eventsPerSecond, isRunning } = useStreamStore()
  return (
    <div className="flex items-center gap-1.5">
      <div className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-allow animate-pulse' : 'bg-zinc-600'}`} />
      <span className="font-mono text-10 text-zinc-500">{eventsPerSecond.toFixed(1)}/s</span>
    </div>
  )
}
