import './index.css'
import { useEffect, useState, useCallback } from 'react'
import { Sidebar } from './components/shell/Sidebar'
import { TopBar } from './components/shell/TopBar'
import { EventList } from './components/events/EventList'
import { EventDetail } from './components/events/EventDetail'
import { CommandPalette } from './components/shell/CommandPalette'
import { Playground } from './components/playground/Playground'
import { PostureView } from './components/posture/PostureView'
import { ErrorBoundary } from './components/shared/ErrorBoundary'
import { useEventsStore } from './stores/events'
import { generateEventStream } from './lib/mock/generators'
import { createEventStream } from './lib/mock/stream'
import { getRoute, getSelectedEventId, navigateTo, selectEventInUrl } from './lib/router'
import type { Route } from './lib/router'

export default function App() {
  const { setEvents, addEvent, selectedId, selectEvent, filteredEvents } = useEventsStore()
  const [route, setRoute] = useState<Route>(getRoute())
  const [paletteOpen, setPaletteOpen] = useState(false)

  // Load initial events and start stream
  useEffect(() => {
    setEvents(generateEventStream(50))
    const stream = createEventStream({ onEvent: addEvent })
    return () => stream.stop()
  }, [setEvents, addEvent])

  // Restore selection from URL on load
  useEffect(() => {
    const id = getSelectedEventId()
    if (id) selectEvent(id)
  }, [selectEvent])

  // Listen for hash changes
  useEffect(() => {
    const onHashChange = () => setRoute(getRoute())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  // Sync selected event to URL
  useEffect(() => {
    if (route === 'runtime') selectEventInUrl(selectedId)
  }, [selectedId, route])

  // Keyboard shortcuts
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault()
      setPaletteOpen(true)
      return
    }
    if (paletteOpen) return

    const target = e.target as HTMLElement
    if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return

    const visible = filteredEvents()
    if (!visible.length) return
    const idx = visible.findIndex(ev => ev.id === selectedId)

    if (e.key === 'j') {
      e.preventDefault()
      const next = Math.min(idx + 1, visible.length - 1)
      selectEvent(visible[Math.max(next, 0)].id)
    } else if (e.key === 'k') {
      e.preventDefault()
      const prev = Math.max(idx - 1, 0)
      selectEvent(visible[prev >= 0 ? prev : 0].id)
    } else if (e.key === '[') {
      e.preventDefault()
      const prev = Math.max(idx - 1, 0)
      if (idx > 0) selectEvent(visible[prev].id)
    } else if (e.key === ']') {
      e.preventDefault()
      const next = Math.min(idx + 1, visible.length - 1)
      if (idx < visible.length - 1) selectEvent(visible[next].id)
    } else if (e.key === 'Escape') {
      selectEvent(null)
    }
  }, [selectedId, selectEvent, filteredEvents, paletteOpen])

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  const handleNavigate = (r: Route) => {
    navigateTo(r)
    setRoute(r)
  }

  const getPlaygroundCmd = () => {
    const hash = window.location.hash
    const match = hash.match(/\?cmd=(.+)/)
    return match ? decodeURIComponent(match[1]) : undefined
  }

  return (
    <ErrorBoundary>
      <div className="bg-base min-h-screen text-zinc-100 font-sans flex flex-col">
        <TopBar onOpenPalette={() => setPaletteOpen(true)} />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar activeRoute={route} onNavigate={handleNavigate} />
          <main className="flex-1 overflow-hidden">
            {route === 'runtime' && (
              <div className="flex h-full overflow-hidden">
                <div className="w-[420px] shrink-0 border-r border-border overflow-hidden">
                  <EventList />
                </div>
                <div className="flex-1 overflow-hidden">
                  <EventDetail />
                </div>
              </div>
            )}
            {route === 'policies' && <Playground initialCommand={getPlaygroundCmd()} />}
            {route === 'posture' && <PostureView />}
          </main>
        </div>
        <CommandPalette
          isOpen={paletteOpen}
          onClose={() => setPaletteOpen(false)}
        />
      </div>
    </ErrorBoundary>
  )
}
