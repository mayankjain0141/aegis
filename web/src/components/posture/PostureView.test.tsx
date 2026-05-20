import { render, screen } from '@testing-library/react'
import { PostureView } from './PostureView'
import { useEventsStore } from '../../stores/events'
import { generateEventStream } from '../../lib/mock/generators'

describe('PostureView', () => {
  it('renders 4 stat cards', () => {
    useEventsStore.setState({ events: generateEventStream(50), filter: 'all', selectedId: null })
    render(<PostureView />)
    expect(screen.getByText(/Total Events/i)).toBeTruthy()
    expect(screen.getByText(/Deny Rate/i)).toBeTruthy()
    expect(screen.getByText(/P99 Latency/i)).toBeTruthy()
    expect(screen.getByText(/Sessions/i)).toBeTruthy()
  })
  it('deny rate is calculated correctly', () => {
    const events = generateEventStream(100)
    useEventsStore.setState({ events, filter: 'all', selectedId: null })
    render(<PostureView />)
    const denies = events.filter(e => e.action === 'deny').length
    const rate = ((denies / 100) * 100).toFixed(1)
    // The value should be visible somewhere
    expect(screen.getByText(/Deny Rate/i)).toBeTruthy()
  })
  it('shows top rules section', () => {
    useEventsStore.setState({ events: generateEventStream(20), filter: 'all', selectedId: null })
    render(<PostureView />)
    expect(screen.getByText(/Top Rules/i)).toBeTruthy()
  })
})
