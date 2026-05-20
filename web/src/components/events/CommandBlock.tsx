import type { AegisEvent } from '../../lib/types'

interface Props { event: AegisEvent }

export function CommandBlock({ event }: Props) {
  const hasWrappers = event.signals.command.wrappers.length > 0
  const isNormalized = event.normalized_cmd !== event.raw_command

  return (
    <div className="bg-panel border border-border rounded p-3 font-mono text-12">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-10 font-sans uppercase tracking-wide text-zinc-600">Command</span>
        {hasWrappers && (
          <span className="text-10 font-sans text-zinc-500">
            wrappers: {event.signals.command.wrappers.join(', ')}
          </span>
        )}
      </div>
      <div className="text-zinc-200">
        <span className="text-zinc-600">$ </span>
        {event.raw_command}
      </div>
      {isNormalized && (
        <div className="mt-2 pt-2 border-t border-border-faint">
          <span className="text-10 font-sans text-zinc-600 mr-2">normalized:</span>
          <span className="text-zinc-400">{event.normalized_cmd}</span>
        </div>
      )}
    </div>
  )
}
