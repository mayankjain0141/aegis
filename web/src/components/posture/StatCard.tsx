interface Props {
  label: string
  value: string
  trend?: string
}

export function StatCard({ label, value, trend }: Props) {
  return (
    <div className="bg-panel border border-border rounded p-4">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">{label}</div>
      <div className="font-mono text-18 font-semibold text-zinc-100">{value}</div>
      {trend && <div className="font-mono text-10 text-zinc-500 mt-1">{trend}</div>}
    </div>
  )
}
