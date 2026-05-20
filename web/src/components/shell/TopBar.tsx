import { useStreamStore } from '../../stores/stream'
import { RateIndicator } from './RateIndicator'
import { Pause, Play } from 'lucide-react'

interface TopBarProps {
  onOpenPalette?: () => void
}

export function TopBar({ onOpenPalette = () => {} }: TopBarProps) {
  const { isRunning, pause, resume } = useStreamStore()

  return (
    <div className="h-10 flex items-center px-4 border-b border-border bg-raised">
      <span className="font-sans text-13 font-semibold text-zinc-200">Aegis</span>
      <span className="ml-2 text-10 font-sans uppercase tracking-wide text-zinc-600">AI Agent Security</span>
      <div className="ml-auto flex items-center gap-3">
        <RateIndicator />
        <button
          onClick={isRunning ? pause : resume}
          className="flex items-center gap-1.5 px-2 py-1 text-10 font-sans text-zinc-500 hover:text-zinc-300 border border-border rounded transition-colors"
          title={isRunning ? 'Pause stream' : 'Resume stream'}
        >
          {isRunning ? <Pause size={10} /> : <Play size={10} />}
          <span>{isRunning ? 'Pause' : 'Resume'}</span>
        </button>
        <button
          className="flex items-center gap-1 px-2 py-1 rounded text-10 font-mono text-zinc-500 hover:text-zinc-300 hover:bg-panel transition-colors"
          onClick={onOpenPalette}
          title="Open command palette"
        >
          ⌘K
        </button>
      </div>
    </div>
  )
}
