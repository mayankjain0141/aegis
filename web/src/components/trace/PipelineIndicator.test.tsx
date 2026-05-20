import { render, screen } from '@testing-library/react'
import { PipelineIndicator } from './PipelineIndicator'
import { generateDenyEvent } from '../../lib/mock/generators'

describe('PipelineIndicator', () => {
  it('renders phase 1 node labels', () => {
    const event = generateDenyEvent()
    event.phase = 1
    event.trace.spans = [
      { name: 'bloom_check', start_us: 0, duration_us: 1, phase: 1 },
      { name: 'allowlist', start_us: 1, duration_us: 2, phase: 1 },
      { name: 'signal_extract', start_us: 3, duration_us: 10, phase: 1 },
      { name: 'rule_eval', start_us: 13, duration_us: 8, phase: 1 },
    ]
    render(<PipelineIndicator event={event} />)
    expect(screen.getByText(/bloom/i)).toBeTruthy()
  })
  it('renders total latency', () => {
    const event = generateDenyEvent()
    event.latency_us = 42
    event.phase = 1
    render(<PipelineIndicator event={event} />)
    expect(screen.getByText(/42/)).toBeTruthy()
  })
  it('renders for phase 2 event with behavioral node', () => {
    const event = generateDenyEvent()
    event.phase = 2
    event.trace.spans = [
      { name: 'bloom_check', start_us: 0, duration_us: 1, phase: 1 },
      { name: 'behavioral', start_us: 50, duration_us: 400, phase: 2 },
      { name: 'rule_eval', start_us: 450, duration_us: 20, phase: 2 },
    ]
    render(<PipelineIndicator event={event} />)
    expect(screen.getByText(/behavioral/i)).toBeTruthy()
  })
  it('renders phase number badge', () => {
    const event = generateDenyEvent()
    event.phase = 1
    render(<PipelineIndicator event={event} />)
    expect(screen.getByText(/P1/)).toBeTruthy()
  })
  it('shows verdict at end', () => {
    const event = generateDenyEvent()
    event.phase = 1
    render(<PipelineIndicator event={event} />)
    expect(screen.getByText(/verdict/i)).toBeTruthy()
  })
})
