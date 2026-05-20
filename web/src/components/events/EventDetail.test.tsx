import { render, screen } from '@testing-library/react'
import { EventDetail } from './EventDetail'
import { useEventsStore } from '../../stores/events'
import { generateEventStream } from '../../lib/mock/generators'

describe('EventDetail', () => {
  beforeEach(() => {
    useEventsStore.setState({ events: [], selectedId: null, filter: 'all' })
  })

  it('shows nothing when no event selected', () => {
    useEventsStore.setState({ events: [], selectedId: null, filter: 'all' })
    const { container } = render(<EventDetail />)
    expect(container.firstChild).toBeFalsy()
  })
  it('shows detail when event is selected', () => {
    const events = generateEventStream(3)
    useEventsStore.setState({ events, selectedId: events[0].id, filter: 'all' })
    render(<EventDetail />)
    expect(screen.getByText(/DENIED|ALLOWED|ESCALATED/)).toBeTruthy()
  })
})
