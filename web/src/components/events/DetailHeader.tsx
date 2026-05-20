import type { AegisEvent } from '../../lib/types'

const PHASE_COLOR: Record<number, string> = { 1: 'text-phase1', 2: 'text-phase2', 3: 'text-phase3' }

interface Props { event: AegisEvent }

export function DetailHeader({ event }: Props) {
  const time = new Date(event.time).toLocaleTimeString('en-US', { hour12: false })
  return (
    <div className="flex flex-wrap items-center gap-3 px-4 py-2 border-b border-border text-10 font-mono text-zinc-500">
      <span className="text-zinc-300">{event.id}</span>
      <span>session: {event.session_id}</span>
      <span>{time}</span>
      <span>{event.latency_us}µs</span>
      <span className={`font-sans font-semibold ${PHASE_COLOR[event.phase]}`}>P{event.phase}</span>
      <span className="text-zinc-600">{event.cwd}</span>
    </div>
  )
}
