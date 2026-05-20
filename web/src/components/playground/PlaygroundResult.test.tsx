import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PlaygroundResult } from './PlaygroundResult'
import { generateDenyEvent, generateAllowEvent } from '../../lib/mock/generators'

describe('PlaygroundResult', () => {
  it('renders verdict for deny event', () => {
    render(<PlaygroundResult event={generateDenyEvent()} />)
    expect(screen.getByText('DENIED')).toBeTruthy()
  })
  it('renders verdict for allow event', () => {
    render(<PlaygroundResult event={generateAllowEvent()} />)
    expect(screen.getByText('ALLOWED')).toBeTruthy()
  })
  it('renders signal breakdown', () => {
    render(<PlaygroundResult event={generateDenyEvent()} />)
    expect(screen.getByText(/Signal Breakdown/i)).toBeTruthy()
  })
  it('renders matched rule', () => {
    const event = generateDenyEvent()
    event.rule = 'data_exfiltration'
    render(<PlaygroundResult event={event} />)
    expect(screen.getAllByText('data_exfiltration').length).toBeGreaterThan(0)
  })
})
