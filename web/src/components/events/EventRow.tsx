import { motion, useAnimation } from 'framer-motion'
import { useEffect } from 'react'
import type { AegisEvent } from '../../lib/types'
import { Badge } from '../shared/Badge'

interface EventRowProps {
  event: AegisEvent
  isSelected: boolean
  onClick: () => void
}

const BORDER: Record<string, string> = {
  deny: 'border-l-deny',
  allow: 'border-l-allow',
  escalate: 'border-l-escalate',
}

export function EventRow({ event, isSelected, onClick }: EventRowProps) {
  const cmd = event.raw_command.length > 48
    ? event.raw_command.slice(0, 48) + '…'
    : event.raw_command

  const controls = useAnimation()
  useEffect(() => {
    if (event.action === 'deny') {
      controls.start({
        backgroundColor: ['#7f1d1d40', '#7f1d1d20', 'transparent'],
        transition: { duration: 0.6, times: [0, 0.3, 1] }
      })
    }
  }, []) // only on mount = only when first rendered

  return (
    <motion.div
      data-testid="event-row"
      data-action={event.action}
      onClick={onClick}
      animate={controls}
      className={`border-l-2 ${BORDER[event.action]} ${isSelected ? 'bg-raised' : 'hover:bg-raised/50'}`}
    >
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.15, ease: 'easeOut' }}
        className="flex items-center gap-2 px-3 py-2 cursor-pointer"
      >
        <Badge action={event.action} />
        <span className="font-mono text-12 text-zinc-300 flex-1 truncate">{cmd}</span>
        <span className="font-mono text-10 text-zinc-500">{event.rule}</span>
        <span className="font-mono text-10 text-zinc-600">{event.latency_us}µs</span>
      </motion.div>
    </motion.div>
  )
}
