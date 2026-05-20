import { render, screen } from '@testing-library/react'
import { CommandBlock } from './CommandBlock'
import { generateDenyEvent } from '../../lib/mock/generators'

describe('CommandBlock', () => {
  it('renders raw_command with monospace styling', () => {
    const event = generateDenyEvent()
    event.raw_command = 'rm -rf /etc/passwd'
    const { container } = render(<CommandBlock event={event} />)
    expect(screen.getByText('rm -rf /etc/passwd')).toBeTruthy()
    expect(container.querySelector('.font-mono')).toBeTruthy()
  })
  it('shows normalized_cmd when different from raw', () => {
    const event = generateDenyEvent()
    event.raw_command = 'sudo env rm -rf /etc/passwd'
    event.normalized_cmd = 'rm -rf /etc/passwd'
    render(<CommandBlock event={event} />)
    expect(screen.getByText('rm -rf /etc/passwd')).toBeTruthy()
    expect(screen.getByText(/normalized/i)).toBeTruthy()
  })
  it('shows wrappers when present', () => {
    const event = generateDenyEvent()
    event.signals.command.wrappers = ['sudo', 'env']
    render(<CommandBlock event={event} />)
    expect(screen.getByText(/sudo/)).toBeTruthy()
  })
})
