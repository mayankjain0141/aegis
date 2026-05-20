import { Shield, Activity, BookOpen, BarChart2 } from 'lucide-react'
import { useEventsStore } from '../../stores/events'
import type { Route } from '../../lib/router'

interface SidebarProps {
  activeRoute?: Route
  onNavigate?: (route: Route) => void
}

export function Sidebar({ activeRoute, onNavigate }: SidebarProps) {
  const { events } = useEventsStore()
  const total = events.length
  const denies = events.filter(e => e.action === 'deny').length
  const denyRate = total > 0 ? ((denies / total) * 100).toFixed(1) : '0.0'

  return (
    <nav className="w-14 flex flex-col items-center bg-raised border-r border-border h-full py-3 gap-1">
      <div className="mb-3">
        <Shield size={20} className="text-zinc-400" />
      </div>
      <NavItem icon={<Activity size={16} />} label="Runtime" active={activeRoute === 'runtime'} onClick={() => onNavigate?.('runtime')} />
      <NavItem icon={<BookOpen size={16} />} label="Policies" active={activeRoute === 'policies'} onClick={() => onNavigate?.('policies')} />
      <NavItem icon={<BarChart2 size={16} />} label="Posture" active={activeRoute === 'posture'} onClick={() => onNavigate?.('posture')} />
      <div className="mt-auto flex flex-col items-center gap-1">
        <div className="flex items-center gap-1">
          <div className="w-1.5 h-1.5 rounded-full bg-allow animate-pulse" />
        </div>
        <span className="text-10 font-sans text-zinc-600">online</span>
        <span className="font-mono text-10 text-zinc-600">{denyRate}%</span>
      </div>
    </nav>
  )
}

function NavItem({ icon, label, active, onClick }: { icon: React.ReactNode; label: string; active?: boolean; onClick?: () => void }) {
  return (
    <button
      className={`w-10 h-10 flex items-center justify-center rounded transition-colors ${active ? 'text-zinc-100 bg-panel' : 'text-zinc-500 hover:text-zinc-300 hover:bg-panel'}`}
      title={label}
      onClick={onClick}
    >
      {icon}
    </button>
  )
}
