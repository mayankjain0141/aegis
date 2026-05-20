import { render, screen } from '@testing-library/react'
import { VerdictCard } from './VerdictCard'
import { generateDenyEvent, generateAllowEvent, generateEscalateEvent } from '../../lib/mock/generators'

describe('VerdictCard', () => {
  it('shows DENIED for deny events', () => {
    render(<VerdictCard event={generateDenyEvent()} />)
    expect(screen.getByText('DENIED')).toBeTruthy()
  })
  it('shows ALLOWED for allow events', () => {
    render(<VerdictCard event={generateAllowEvent()} />)
    expect(screen.getByText('ALLOWED')).toBeTruthy()
  })
  it('shows ESCALATED for escalate events', () => {
    render(<VerdictCard event={generateEscalateEvent()} />)
    expect(screen.getByText('ESCALATED')).toBeTruthy()
  })
  it('shows rule name', () => {
    const event = generateDenyEvent()
    event.rule = 'data_exfiltration'
    render(<VerdictCard event={event} />)
    expect(screen.getByText('data_exfiltration')).toBeTruthy()
  })
  it('shows confidence as percentage', () => {
    const event = generateDenyEvent()
    event.confidence = 0.95
    render(<VerdictCard event={event} />)
    expect(screen.getByText('95%')).toBeTruthy()
  })
  it('deny card has red surface class', () => {
    const { container } = render(<VerdictCard event={generateDenyEvent()} />)
    expect(container.firstChild?.toString()).toBeTruthy()
    // Check bg-deny/10 or similar is in the className
    const el = container.firstChild as HTMLElement
    expect(el.className).toMatch(/deny/)
  })
})
