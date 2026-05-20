import type { SignalBundle } from '../../lib/types'

interface Props { signals: SignalBundle; size?: number }

export function RadarChart({ signals, size = 160 }: Props) {
  const center = size / 2
  const radius = size * 0.38
  const labels = ['Tool', 'Command', 'Path', 'Network', 'DLP', 'Evasion']
  const scores = [
    signals.tool_class.score,
    signals.command.max_danger,
    signals.path.max_risk,
    signals.network.score,
    signals.dlp.score,
    signals.evasion.score,
  ]
  const n = labels.length
  const angleStep = (2 * Math.PI) / n
  const startAngle = -Math.PI / 2

  // Convert polar to cartesian
  const point = (r: number, i: number) => {
    const a = startAngle + i * angleStep
    return { x: center + r * Math.cos(a), y: center + r * Math.sin(a) }
  }

  // Background rings
  const rings = [0.25, 0.5, 0.75, 1.0]

  // Axis endpoints
  const axes = labels.map((_, i) => point(radius, i))

  // Score polygon
  const polygon = scores.map((s, i) => point(radius * s, i))
  const polygonPath = polygon.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ') + ' Z'

  // Threshold ring at 0.6 danger level
  const dangerRing = Array.from({ length: n }, (_, i) => point(radius * 0.6, i))
  const dangerPath = dangerRing.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ') + ' Z'

  const maxScore = Math.max(...scores)
  const fillColor = maxScore > 0.7 ? '#ef4444' : maxScore > 0.4 ? '#f59e0b' : '#3b82f6'

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {/* Background rings */}
      {rings.map(r => {
        const pts = Array.from({ length: n }, (_, i) => point(radius * r, i))
        const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ') + ' Z'
        return <path key={r} d={path} fill="none" stroke="#27272a" strokeWidth="0.5" />
      })}

      {/* Axis lines */}
      {axes.map((p, i) => (
        <line key={i} x1={center} y1={center} x2={p.x} y2={p.y} stroke="#27272a" strokeWidth="0.5" />
      ))}

      {/* Danger threshold ring */}
      <path d={dangerPath} fill="none" stroke="#ef444440" strokeWidth="1" strokeDasharray="2,2" />

      {/* Score polygon */}
      <path d={polygonPath} fill={fillColor + '30'} stroke={fillColor} strokeWidth="1.5" />

      {/* Score dots */}
      {polygon.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r="2.5" fill={fillColor} />
      ))}

      {/* Labels */}
      {labels.map((label, i) => {
        const lp = point(radius + 14, i)
        const textAnchor = lp.x < center - 2 ? 'end' : lp.x > center + 2 ? 'start' : 'middle'
        return (
          <text key={i} x={lp.x} y={lp.y + 3} textAnchor={textAnchor}
            fontSize="8" fill="#71717a" fontFamily="Inter, system-ui">
            {label}
          </text>
        )
      })}
    </svg>
  )
}
