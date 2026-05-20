import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { EventRow } from './EventRow'
import { generateDenyEvent, generateAllowEvent } from '../../lib/mock/generators'

describe('EventRow', () => {
  it('renders command truncated at 48 chars', () => {
    const event = generateAllowEvent()
    event.raw_command = 'a'.repeat(60)
    render(<EventRow event={event} isSelected={false} onClick={() => {}} />)
    const text = screen.getByText(/a{48}…/)
    expect(text).toBeTruthy()
  })
  it('calls onClick when clicked', async () => {
    const onClick = vi.fn()
    const event = generateAllowEvent()
    const { container } = render(<EventRow event={event} isSelected={false} onClick={onClick} />)
    await userEvent.click(container.firstChild as Element)
    expect(onClick).toHaveBeenCalled()
  })
  it('deny row has red left border class', () => {
    const event = generateDenyEvent()
    const { container } = render(<EventRow event={event} isSelected={false} onClick={() => {}} />)
    expect(container.firstChild).toHaveClass('border-l-deny')
  })
})
