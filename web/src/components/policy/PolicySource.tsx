interface Props {
  file: string
  line: number
  snippet: string
  condition: string
}

export function PolicySource({ file, line, condition }: Props) {
  return (
    <div className="border border-border rounded p-3 bg-panel text-12">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Policy Source</div>
      <div className="font-mono text-zinc-400">
        <span className="text-zinc-300">{file}</span>
        <span className="text-zinc-600">:{line}</span>
      </div>
      {condition && (
        <div className="mt-2 font-mono text-10 text-zinc-500 bg-base rounded p-2">
          {condition}
        </div>
      )}
    </div>
  )
}
