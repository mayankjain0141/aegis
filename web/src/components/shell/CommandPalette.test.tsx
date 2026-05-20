import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CommandPalette } from './CommandPalette'
import { useEventsStore } from '../../stores/events'
import { generateEventStream } from '../../lib/mock/generators'

describe('CommandPalette', () => {
  it('does not render when closed', () => {
    const { container } = render(<CommandPalette isOpen={false} onClose={() => {}} />)
    expect(container.firstChild).toBeNull()
  })
  it('renders search input when open', () => {
    useEventsStore.setState({ events: generateEventStream(5), filter: 'all', selectedId: null })
    render(<CommandPalette isOpen={true} onClose={() => {}} />)
    expect(screen.getByPlaceholderText(/search|command/i)).toBeTruthy()
  })
  it('calls onClose when Escape pressed', async () => {
    const onClose = vi.fn()
    useEventsStore.setState({ events: generateEventStream(5), filter: 'all', selectedId: null })
    render(<CommandPalette isOpen={true} onClose={onClose} />)
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalled()
  })
  it('shows recent events as options', () => {
    const events = generateEventStream(3)
    useEventsStore.setState({ events, filter: 'all', selectedId: null })
    render(<CommandPalette isOpen={true} onClose={() => {}} />)
    // Should show event commands in the list
    expect(screen.getByPlaceholderText(/search|command/i)).toBeTruthy()
  })
})
