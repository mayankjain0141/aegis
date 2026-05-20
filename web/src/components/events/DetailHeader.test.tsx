import { render, screen } from '@testing-library/react'
import { DetailHeader } from './DetailHeader'
import { generateDenyEvent } from '../../lib/mock/generators'

describe('DetailHeader', () => {
  it('shows event ID', () => {
    const event = generateDenyEvent()
    event.id = 'test-event-id-123'
    render(<DetailHeader event={event} />)
    expect(screen.getByText(/test-event-id-123/)).toBeTruthy()
  })
  it('shows session ID', () => {
    const event = generateDenyEvent()
    event.session_id = 'sess-abc'
    render(<DetailHeader event={event} />)
    expect(screen.getByText(/sess-abc/)).toBeTruthy()
  })
  it('shows latency', () => {
    const event = generateDenyEvent()
    event.latency_us = 42
    render(<DetailHeader event={event} />)
    expect(screen.getByText(/42/)).toBeTruthy()
  })
  it('shows phase badge with phase number', () => {
    const event = generateDenyEvent()
    event.phase = 1
    render(<DetailHeader event={event} />)
    expect(screen.getByText(/P1/)).toBeTruthy()
  })
})
