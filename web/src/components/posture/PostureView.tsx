import { useEventsStore } from '../../stores/events'
import { StatCard } from './StatCard'
import { Sparkline } from './Sparkline'

export function PostureView() {
  const { events } = useEventsStore()
  const total = events.length
  const denies = events.filter(e => e.action === 'deny').length
  const denyRate = total > 0 ? ((denies / total) * 100).toFixed(1) : '0.0'

  const latencies = events.map(e => e.latency_us).sort((a, b) => a - b)
  const p99 = latencies.length > 0 ? latencies[Math.floor(latencies.length * 0.99)] : 0

  const sessionIds = new Set(events.map(e => e.session_id))

  // Top rules by fire count
  const ruleCounts = events.reduce<Record<string, number>>((acc, e) => {
    acc[e.rule] = (acc[e.rule] || 0) + 1
    return acc
  }, {})
  const topRules = Object.entries(ruleCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  // Sparkline: deny rate across 10 time buckets
  const sparklineData = (() => {
    if (events.length < 10) return []
    const bucketSize = Math.floor(events.length / 10)
    return Array.from({ length: 10 }, (_, i) => {
      const bucket = events.slice(i * bucketSize, (i + 1) * bucketSize)
      const bucketDenies = bucket.filter(e => e.action === 'deny').length
      return bucket.length > 0 ? bucketDenies / bucket.length : 0
    })
  })()

  // Trend: delta between first half and second half deny rate
  const firstHalf = events.slice(0, Math.floor(events.length / 2))
  const secondHalf = events.slice(Math.floor(events.length / 2))
  const firstRate = firstHalf.filter(e => e.action === 'deny').length / (firstHalf.length || 1)
  const secondRate = secondHalf.filter(e => e.action === 'deny').length / (secondHalf.length || 1)
  const trend = ((secondRate - firstRate) * 100).toFixed(1)
  const trendStr = events.length > 0
    ? (Number(trend) > 0 ? `+${trend}%` : `${trend}%`)
    : undefined

  return (
    <div className="p-6 overflow-y-auto">
      <div className="text-14 font-sans font-semibold text-zinc-200 mb-4">Security Posture</div>
      <div className="grid grid-cols-4 gap-3 mb-6">
        <StatCard label="Total Events" value={total.toLocaleString()} />
        <div className="bg-panel border border-border rounded p-4">
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Deny Rate</div>
          <div className="flex items-end gap-3">
            <div className="font-mono text-18 font-semibold text-zinc-100">{denyRate}%</div>
            {sparklineData.length >= 2 && (
              <div className="mb-1">
                <Sparkline data={sparklineData} color="#ef4444" />
              </div>
            )}
          </div>
          {trendStr && <div className="font-mono text-10 text-zinc-500 mt-1">{trendStr}</div>}
        </div>
        <StatCard label="P99 Latency" value={`${p99}µs`} />
        <StatCard label="Sessions" value={sessionIds.size.toString()} />
      </div>
      <div className="border border-border rounded p-4 bg-panel">
        <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-3">Top Rules</div>
        <div className="flex flex-col gap-2">
          {topRules.map(([rule, count]) => (
            <div key={rule} className="flex items-center justify-between">
              <span className="font-mono text-12 text-zinc-300">{rule}</span>
              <span className="font-mono text-12 text-zinc-500">{count}</span>
            </div>
          ))}
          {topRules.length === 0 && (
            <span className="text-13 text-zinc-600">No events yet</span>
          )}
        </div>
      </div>
    </div>
  )
}
