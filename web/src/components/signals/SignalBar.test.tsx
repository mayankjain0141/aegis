import { render, screen } from '@testing-library/react'
import { SignalBar } from './SignalBar'

describe('SignalBar', () => {
  it('renders signal name and score', () => {
    render(<SignalBar name="Command" score={0.8} isTriggered={false} />)
    expect(screen.getByText('Command')).toBeTruthy()
    expect(screen.getByText('0.80')).toBeTruthy()
  })
  it('bar width is proportional to score', () => {
    const { container } = render(<SignalBar name="Path" score={0.6} isTriggered={false} />)
    const fill = container.querySelector('[data-fill]') as HTMLElement
    expect(fill?.style.width).toBe('60%')
  })
  it('score > 0.6 has red color class', () => {
    const { container } = render(<SignalBar name="Path" score={0.8} isTriggered={false} />)
    const fill = container.querySelector('[data-fill]') as HTMLElement
    expect(fill?.className).toMatch(/deny/)
  })
  it('score 0.3-0.6 has amber color class', () => {
    const { container } = render(<SignalBar name="Path" score={0.45} isTriggered={false} />)
    const fill = container.querySelector('[data-fill]') as HTMLElement
    expect(fill?.className).toMatch(/escalate/)
  })
  it('score < 0.3 has neutral color class', () => {
    const { container } = render(<SignalBar name="Path" score={0.1} isTriggered={false} />)
    const fill = container.querySelector('[data-fill]') as HTMLElement
    expect(fill?.className).toMatch(/zinc/)
  })
  it('shows TRIGGERED badge when isTriggered is true', () => {
    render(<SignalBar name="Path" score={0.9} isTriggered={true} />)
    expect(screen.getByText('TRIGGERED')).toBeTruthy()
  })
  it('does not show TRIGGERED badge when false', () => {
    render(<SignalBar name="Path" score={0.9} isTriggered={false} />)
    expect(screen.queryByText('TRIGGERED')).toBeNull()
  })
  it('shows zero score as 0.00', () => {
    render(<SignalBar name="Network" score={0} isTriggered={false} />)
    expect(screen.getByText('0.00')).toBeTruthy()
  })
})
