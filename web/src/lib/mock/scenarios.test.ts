import { describe, it, expect } from 'vitest'
import { generateNextEvent, generateAttackBurst } from './scenarios'
import type { AegisEvent } from '../types'

describe('generateNextEvent', () => {
  it('returns a valid AegisEvent', () => {
    const event = generateNextEvent([])
    expect(event.id).toBeTruthy()
    expect(event.action).toMatch(/allow|deny|escalate/)
  })
  it('returns deny with retry flag when last event was deny', () => {
    const deny = { action: 'deny' } as AegisEvent
    // Run many times to hit the 30% retry branch
    let gotRetry = false
    for (let i = 0; i < 50; i++) {
      const e = generateNextEvent([deny])
      if (e.behavioral?.retry_after_deny) { gotRetry = true; break }
    }
    expect(gotRetry).toBe(true)
  })
})

describe('generateAttackBurst', () => {
  it('returns 5 events', () => {
    expect(generateAttackBurst()).toHaveLength(5)
  })
  it('first event is allow (recon)', () => {
    expect(generateAttackBurst()[0].action).toBe('allow')
  })
  it('contains at least 3 deny events', () => {
    const burst = generateAttackBurst()
    expect(burst.filter(e => e.action === 'deny').length).toBeGreaterThanOrEqual(3)
  })
})
