import { useRef, useState, useEffect } from 'react'
import { List } from 'react-window'
import { useEventsStore } from '../../stores/events'
import { EventRow } from './EventRow'
import { Skeleton } from '../shared/Skeleton'
import type { Action, AegisEvent } from '../../lib/types'

const FILTERS: Array<{ label: string; value: 'all' | Action }> = [
  { label: 'All', value: 'all' },
  { label: 'Deny', value: 'deny' },
  { label: 'Allow', value: 'allow' },
  { label: 'Escalate', value: 'escalate' },
]

interface RowProps {
  events: AegisEvent[]
  selectedId: string | null
  onSelect: (id: string) => void
}

function Row({
  index,
  style,
  events,
  selectedId,
  onSelect,
}: {
  index: number
  style: React.CSSProperties
  ariaAttributes: object
  events: AegisEvent[]
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const event = events[index]
  return (
    <div style={style}>
      <EventRow
        event={event}
        isSelected={selectedId === event.id}
        onClick={() => onSelect(event.id)}
      />
    </div>
  )
}

export function EventList() {
  const { filter, setFilter, filteredEvents, selectEvent, selectedId } = useEventsStore()
  const events = filteredEvents()
  // isInitialLoad starts true — shows skeleton on the very first render cycle
  // useEffect clears it after mount so the "no events" state shows correctly
  const [isInitialLoad, setIsInitialLoad] = useState(true)
  const hasEventsRef = useRef(false)
  if (events.length > 0) hasEventsRef.current = true

  useEffect(() => {
    setIsInitialLoad(false)
  }, [])

  if (events.length === 0) {
    if (isInitialLoad && !hasEventsRef.current) {
      return (
        <div className="flex flex-col h-full">
          <FilterBar filter={filter} setFilter={setFilter} />
          <div className="flex flex-col gap-0.5 p-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </div>
      )
    }
    return (
      <div className="flex flex-col h-full">
        <FilterBar filter={filter} setFilter={setFilter} />
        <div className="flex-1 flex items-center justify-center text-13 text-zinc-600">No events</div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <FilterBar filter={filter} setFilter={setFilter} />
      <div className="flex-1 min-h-0">
        <List<RowProps>
          defaultHeight={600}
          rowCount={events.length}
          rowHeight={40}
          rowComponent={Row}
          rowProps={{ events, selectedId, onSelect: selectEvent }}
          style={{ height: '100%' }}
        />
      </div>
    </div>
  )
}

function FilterBar({ filter, setFilter }: { filter: string; setFilter: (f: 'all' | Action) => void }) {
  return (
    <div className="flex gap-1 px-3 py-2 border-b border-border">
      {FILTERS.map(f => (
        <button
          key={f.value}
          onClick={() => setFilter(f.value)}
          className={`px-2 py-1 text-10 font-sans uppercase tracking-wide rounded transition-colors ${filter === f.value ? 'bg-raised text-zinc-200' : 'text-zinc-500 hover:text-zinc-300'}`}
        >
          {f.label}
        </button>
      ))}
    </div>
  )
}
