import { useState } from 'react'
import { PlaygroundInput } from './PlaygroundInput'
import { PlaygroundResult } from './PlaygroundResult'
import { evaluate } from '../../lib/mock/evaluate'
import type { AegisEvent } from '../../lib/types'

interface Props {
  initialCommand?: string
}

export function Playground({ initialCommand }: Props) {
  const [result, setResult] = useState<AegisEvent | null>(null)

  const handleEvaluate = (command: string) => {
    const { event } = evaluate(command)
    setResult(event)
  }

  return (
    <div className="p-6 max-w-2xl">
      <h1 className="text-18 font-sans font-semibold text-zinc-200 mb-4">Policy Playground</h1>
      <PlaygroundInput onEvaluate={handleEvaluate} initialCommand={initialCommand} />
      {result && <PlaygroundResult event={result} />}
    </div>
  )
}
