import { Command } from 'cmdk'
import { useEventsStore } from '../../stores/events'
import type { AegisEvent } from '../../lib/types'

interface Props {
  isOpen: boolean
  onClose: () => void
  onSelectEvent?: (id: string) => void
}

export function CommandPalette({ isOpen, onClose, onSelectEvent }: Props) {
  const { events, selectEvent } = useEventsStore()

  const filteredEvents = events.slice(0, 10)

  const handleSelect = (event: AegisEvent) => {
    selectEvent(event.id)
    onSelectEvent?.(event.id)
    onClose()
  }

  return (
    <Command.Dialog
      open={isOpen}
      onOpenChange={(open) => { if (!open) onClose() }}
      className="fixed inset-0 z-50"
    >
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/60" onClick={onClose} />

      <div className="fixed top-[15vh] left-1/2 -translate-x-1/2 w-full max-w-lg bg-raised border border-border-strong rounded shadow-2xl overflow-hidden">
        <Command.Input
          className="w-full bg-transparent px-4 py-3 font-mono text-13 text-zinc-200 placeholder:text-zinc-600 focus:outline-none border-b border-border"
          placeholder="Search commands, rules..."
        />
        <Command.List className="max-h-80 overflow-y-auto py-1">
          <Command.Empty className="px-4 py-3 text-13 font-sans text-zinc-600">
            No results
          </Command.Empty>
          <Command.Group
            heading="Recent Events"
            className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-10 [&_[cmdk-group-heading]]:font-sans [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-zinc-600"
          >
            {filteredEvents.map(event => (
              <Command.Item
                key={event.id}
                value={`${event.raw_command} ${event.rule}`}
                onSelect={() => handleSelect(event)}
                className="flex items-center gap-3 px-4 py-2 cursor-pointer data-[selected=true]:bg-panel aria-selected:bg-panel"
              >
                <span className={`text-10 font-mono shrink-0 ${event.action === 'deny' ? 'text-deny' : event.action === 'escalate' ? 'text-escalate' : 'text-allow'}`}>
                  {event.action.toUpperCase()}
                </span>
                <span className="font-mono text-12 text-zinc-300 flex-1 truncate">{event.raw_command}</span>
                <span className="font-mono text-10 text-zinc-600 shrink-0">{event.rule}</span>
              </Command.Item>
            ))}
          </Command.Group>
          <Command.Group
            heading="Actions"
            className="[&_[cmdk-group-heading]]:px-4 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-10 [&_[cmdk-group-heading]]:font-sans [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-zinc-600"
          >
            <Command.Item
              value="simulate playground"
              onSelect={() => { window.location.hash = '#/policies'; onClose() }}
              className="flex items-center gap-3 px-4 py-2 cursor-pointer data-[selected=true]:bg-panel aria-selected:bg-panel"
            >
              <span className="font-sans text-12 text-zinc-400">→</span>
              <span className="font-sans text-13 text-zinc-300">Simulate in Playground</span>
            </Command.Item>
            <Command.Item
              value="posture security"
              onSelect={() => { window.location.hash = '#/posture'; onClose() }}
              className="flex items-center gap-3 px-4 py-2 cursor-pointer data-[selected=true]:bg-panel aria-selected:bg-panel"
            >
              <span className="font-sans text-12 text-zinc-400">→</span>
              <span className="font-sans text-13 text-zinc-300">View Security Posture</span>
            </Command.Item>
            <Command.Item
              value="runtime view"
              onSelect={() => { window.location.hash = '#/runtime'; onClose() }}
              className="flex items-center gap-3 px-4 py-2 cursor-pointer data-[selected=true]:bg-panel aria-selected:bg-panel"
            >
              <span className="font-sans text-12 text-zinc-400">→</span>
              <span className="font-sans text-13 text-zinc-300">View Runtime</span>
            </Command.Item>
          </Command.Group>
        </Command.List>
      </div>
    </Command.Dialog>
  )
}
