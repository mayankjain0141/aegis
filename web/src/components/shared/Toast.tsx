interface Props {
  message: string
  visible: boolean
}

export function Toast({ message, visible }: Props) {
  if (!visible) return null
  return (
    <div className="fixed bottom-4 right-4 bg-raised border border-border rounded px-3 py-2 text-13 font-sans text-zinc-200 shadow-lg z-50">
      {message}
    </div>
  )
}
