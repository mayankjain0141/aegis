import { describe, it, expect, beforeEach } from 'vitest'
import { getRoute, getSelectedEventId, navigateTo } from './router'

describe('router', () => {
  beforeEach(() => { window.location.hash = '' })

  it('returns runtime as default route', () => {
    expect(getRoute()).toBe('runtime')
  })
  it('returns policies route from hash', () => {
    window.location.hash = '#/policies'
    expect(getRoute()).toBe('policies')
  })
  it('returns posture route from hash', () => {
    window.location.hash = '#/posture'
    expect(getRoute()).toBe('posture')
  })
  it('returns null when no event in hash', () => {
    window.location.hash = '#/runtime'
    expect(getSelectedEventId()).toBeNull()
  })
  it('returns event ID from hash', () => {
    window.location.hash = '#/events/abc123'
    expect(getSelectedEventId()).toBe('abc123')
  })
})
