import { describe, it, expect } from 'vitest'
import { generateEvent, generateDenyEvent, generateAllowEvent, generateEscalateEvent, generateEventStream } from './generators'

describe('generateEvent', () => {
  it('returns valid AegisEvent with all required fields', () => {
    const e = generateEvent()
    expect(e.id).toBeTruthy()
    expect(e.time).toBeTruthy()
    expect(e.action).toMatch(/allow|deny|escalate/)
    expect(e.signals).toBeDefined()
    expect(e.trace).toBeDefined()
    expect(e.eval_chain).toBeDefined()
  })
  it('generates unique IDs for each call', () => {
    const a = generateEvent()
    const b = generateEvent()
    expect(a.id).not.toBe(b.id)
  })
})

describe('generateDenyEvent', () => {
  it('has action deny', () => expect(generateDenyEvent().action).toBe('deny'))
  it('has composite_score > 0.5', () => expect(generateDenyEvent().composite_score).toBeGreaterThan(0.5))
  it('has severity set', () => expect(generateDenyEvent().severity).toBeTruthy())
  it('has at least one signal score > 0.6', () => {
    const e = generateDenyEvent()
    const scores = [
      e.signals.tool_class.score, e.signals.command.max_danger,
      e.signals.path.max_risk, e.signals.network.score,
      e.signals.dlp.score, e.signals.evasion.score,
    ]
    expect(scores.some(s => s > 0.6)).toBe(true)
  })
  it('eval_chain has exactly one match step', () => {
    const e = generateDenyEvent()
    expect(e.eval_chain.filter(s => s.result === 'match')).toHaveLength(1)
  })
  it('eval_chain match step has same rule as event.rule', () => {
    const e = generateDenyEvent()
    const match = e.eval_chain.find(s => s.result === 'match')
    expect(match?.rule).toBe(e.rule)
  })
  it('trace spans sum to approximately latency_us within 20%', () => {
    const e = generateDenyEvent()
    const spanSum = e.trace.spans.reduce((acc, s) => acc + s.duration_us, 0)
    expect(spanSum).toBeGreaterThan(e.latency_us * 0.8)
    expect(spanSum).toBeLessThan(e.latency_us * 1.2)
  })
})

describe('generateAllowEvent', () => {
  it('has action allow', () => expect(generateAllowEvent().action).toBe('allow'))
  it('has composite_score < 0.4', () => expect(generateAllowEvent().composite_score).toBeLessThan(0.4))
})

describe('generateEventStream', () => {
  it('returns exactly N events', () => expect(generateEventStream(50)).toHaveLength(50))
  it('events are in chronological order', () => {
    const events = generateEventStream(20)
    for (let i = 1; i < events.length; i++) {
      expect(new Date(events[i].time).getTime()).toBeGreaterThanOrEqual(new Date(events[i-1].time).getTime())
    }
  })
  it('distribution over 100 events', () => {
    const events = generateEventStream(100)
    const allows = events.filter(e => e.action === 'allow').length
    const denies = events.filter(e => e.action === 'deny').length
    const escalates = events.filter(e => e.action === 'escalate').length
    expect(allows).toBeGreaterThan(60)
    expect(denies).toBeGreaterThanOrEqual(8)
    expect(escalates).toBeGreaterThanOrEqual(3)
  })
  it('phase 2 events have behavioral field', () => {
    const events = generateEventStream(100)
    const p2 = events.filter(e => e.phase === 2)
    expect(p2.length).toBeGreaterThan(0)
    p2.forEach(e => expect(e.behavioral).toBeDefined())
  })
  it('phase 3 events have llm field', () => {
    const events = generateEventStream(200)
    const p3 = events.filter(e => e.phase === 3)
    if (p3.length > 0) p3.forEach(e => expect(e.llm).toBeDefined())
  })
})
