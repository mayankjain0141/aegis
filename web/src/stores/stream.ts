import { create } from 'zustand'

type Speed = 1 | 2 | 4

interface StreamStore {
  isRunning: boolean
  speed: Speed
  eventsPerSecond: number
  _eventTimes: number[]
  pause: () => void
  resume: () => void
  setSpeed: (speed: Speed) => void
  recordEvent: () => void
}

export const useStreamStore = create<StreamStore>((set, get) => ({
  isRunning: true,
  speed: 1,
  eventsPerSecond: 0,
  _eventTimes: [],
  pause: () => set({ isRunning: false }),
  resume: () => set({ isRunning: true }),
  setSpeed: (speed) => set({ speed }),
  recordEvent: () => {
    const now = Date.now()
    // Keep last 10 seconds of event times for rate calculation
    const times = [...get()._eventTimes, now].filter((t: number) => now - t < 10000)
    const eps = times.length / 10
    set({ _eventTimes: times, eventsPerSecond: Math.round(eps * 10) / 10 })
  },
}))
