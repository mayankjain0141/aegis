import { describe, it, expect, beforeEach } from 'vitest'
import { useEventsStore } from './events'
import { act } from '@testing-library/react'

describe('useEventsStore', () => {
  beforeEach(() => useEventsStore.setState({ events: [], selectedId: null, filter: 'all' }))

  it('initializes with empty events', () => {
    expect(useEventsStore.getState().events).toHaveLength(0)
  })
  it('setFilter updates filter', () => {
    act(() => useEventsStore.getState().setFilter('deny'))
    expect(useEventsStore.getState().filter).toBe('deny')
  })
  it('selectEvent updates selectedId', () => {
    act(() => useEventsStore.getState().selectEvent('abc'))
    expect(useEventsStore.getState().selectedId).toBe('abc')
  })
  it('filteredEvents returns all events when filter is all', () => {
    const events = [{ id: '1', action: 'deny' }, { id: '2', action: 'allow' }] as any
    useEventsStore.setState({ events, filter: 'all' })
    expect(useEventsStore.getState().filteredEvents()).toHaveLength(2)
  })
  it('filteredEvents returns only deny events when filter is deny', () => {
    const events = [{ id: '1', action: 'deny' }, { id: '2', action: 'allow' }] as any
    useEventsStore.setState({ events, filter: 'deny' })
    expect(useEventsStore.getState().filteredEvents()).toHaveLength(1)
  })
})
