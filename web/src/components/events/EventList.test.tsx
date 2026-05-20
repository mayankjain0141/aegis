import { render, screen } from '@testing-library/react'
import { EventList } from './EventList'
import { useEventsStore } from '../../stores/events'
import { generateEventStream } from '../../lib/mock/generators'

describe('EventList', () => {
  it('shows empty state when no events', () => {
    useEventsStore.setState({ events: [], filter: 'all', selectedId: null })
    render(<EventList height={400} />)
    expect(screen.getByText(/no events/i)).toBeTruthy()
  })
  it('filter buttons exist', () => {
    useEventsStore.setState({ events: generateEventStream(5), filter: 'all', selectedId: null })
    render(<EventList height={400} />)
    expect(screen.getByRole('button', { name: /^all$/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^deny$/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^allow$/i })).toBeTruthy()
  })
})
