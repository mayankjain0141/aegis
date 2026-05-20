import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createEventStream } from './stream'

describe('createEventStream', () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => { vi.useRealTimers() })

  it('calls onEvent after interval', () => {
    const onEvent = vi.fn()
    const ctrl = createEventStream({ intervalMs: [100, 100], onEvent })
    vi.advanceTimersByTime(200)
    expect(onEvent).toHaveBeenCalled()
    ctrl.stop()
  })

  it('stops calling onEvent after stop()', () => {
    const onEvent = vi.fn()
    const ctrl = createEventStream({ intervalMs: [100, 100], onEvent })
    vi.advanceTimersByTime(150)
    ctrl.stop()
    const callCount = onEvent.mock.calls.length
    vi.advanceTimersByTime(500)
    expect(onEvent.mock.calls.length).toBe(callCount)
  })

  it('does not emit while paused', () => {
    const onEvent = vi.fn()
    const ctrl = createEventStream({ intervalMs: [100, 100], onEvent })
    ctrl.pause()
    vi.advanceTimersByTime(500)
    expect(onEvent).not.toHaveBeenCalled()
    ctrl.stop()
  })

  it('resumes emitting after resume()', () => {
    const onEvent = vi.fn()
    const ctrl = createEventStream({ intervalMs: [100, 100], onEvent })
    ctrl.pause()
    vi.advanceTimersByTime(200)
    ctrl.resume()
    vi.advanceTimersByTime(200)
    expect(onEvent).toHaveBeenCalled()
    ctrl.stop()
  })
})
