import { create } from 'zustand'
import type { AegisEvent, Action } from '../lib/types'

type Filter = 'all' | Action

interface EventsStore {
  events: AegisEvent[]
  selectedId: string | null
  filter: Filter
  setEvents: (events: AegisEvent[]) => void
  addEvent: (event: AegisEvent) => void
  selectEvent: (id: string | null) => void
  setFilter: (filter: Filter) => void
  filteredEvents: () => AegisEvent[]
}

export const useEventsStore = create<EventsStore>((set, get) => ({
  events: [],
  selectedId: null,
  filter: 'all',
  setEvents: (events) => set({ events }),
  addEvent: (event) => set(state => ({ events: [event, ...state.events] })),
  selectEvent: (id) => set({ selectedId: id }),
  setFilter: (filter) => set({ filter }),
  filteredEvents: () => {
    const { events, filter } = get()
    if (filter === 'all') return events
    return events.filter(e => e.action === filter)
  },
}))
