import type { AegisEvent } from '../types'
import { generateNextEvent, generateAttackBurst } from './scenarios'

export interface StreamOptions {
  intervalMs?: [number, number]  // [min, max] random interval range
  onEvent: (event: AegisEvent) => void
}

export interface StreamControl {
  pause: () => void
  resume: () => void
  stop: () => void
}

export function createEventStream(options: StreamOptions): StreamControl {
  const [minMs, maxMs] = options.intervalMs ?? [800, 2000]
  let paused = false
  let stopped = false
  let timeoutId: ReturnType<typeof setTimeout> | null = null
  const history: AegisEvent[] = []
  let attackScheduled = false

  const scheduleNext = () => {
    if (stopped) return
    const delay = minMs + Math.random() * (maxMs - minMs)
    timeoutId = setTimeout(() => {
      if (stopped) return
      if (!paused) {
        const event = generateNextEvent(history)
        history.push(event)
        options.onEvent(event)

        // Schedule attack burst at ~8s
        if (!attackScheduled && history.length > 4) {
          attackScheduled = true
          setTimeout(() => {
            if (stopped || paused) return
            const burst = generateAttackBurst()
            burst.forEach((e, i) => {
              setTimeout(() => {
                if (!stopped) {
                  history.push(e)
                  options.onEvent(e)
                }
              }, i * 600)
            })
          }, 4000)
        }
      }
      scheduleNext()
    }, delay)
  }

  scheduleNext()

  return {
    pause: () => { paused = true },
    resume: () => { paused = false },
    stop: () => {
      stopped = true
      if (timeoutId) clearTimeout(timeoutId)
    },
  }
}
