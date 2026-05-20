import type { AegisEvent } from '../../../lib/types'
import { useEventsStore } from '../../../stores/events'
import { Badge } from '../../shared/Badge'

interface Props { event: AegisEvent }

export function RelatedTab({ event }: Props) {
  const { events, selectEvent } = useEventsStore()
  const sameRule = events.filter(e => e.id !== event.id && e.rule === event.rule).slice(0, 8)
  const sameSession = events.filter(e => e.id !== event.id && e.session_id === event.session_id).slice(0, 8)

  return (
    <div className="flex flex-col gap-3 p-4 overflow-y-auto flex-1 min-h-0">
      <Section title={`Same Rule: ${event.rule}`} items={sameRule} onSelect={selectEvent} />
      {sameSession.length > 0 && (
        <Section title="Same Session" items={sameSession} onSelect={selectEvent} />
      )}
      {sameRule.length === 0 && sameSession.length === 0 && (
        <div className="text-13 font-sans text-zinc-600">No related events in current view.</div>
      )}
    </div>
  )
}

function Section({ title, items, onSelect }: { title: string; items: AegisEvent[]; onSelect: (id: string) => void }) {
  if (items.length === 0) return null
  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">{title}</div>
      {items.map(e => (
        <div key={e.id} onClick={() => onSelect(e.id)}
          className="flex items-center gap-2 py-1.5 cursor-pointer hover:bg-raised/50 rounded px-1 -mx-1">
          <Badge action={e.action} />
          <span className="font-mono text-12 text-zinc-300 flex-1 truncate">{e.raw_command}</span>
          <span className="font-mono text-10 text-zinc-600">{e.latency_us}µs</span>
        </div>
      ))}
    </div>
  )
}
