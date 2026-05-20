import type { AegisEvent } from '../../../lib/types'

interface Props { event: AegisEvent }

function derive(event: AegisEvent) {
  const cmd = event.raw_command.toLowerCase()
  const sigs = event.signals
  return {
    threat: event.action === 'deny' ? (event.severity === 'critical' ? 'System Destruction' : event.severity === 'high' ? 'Data Exfiltration' : 'Policy Violation') : 'None',
    blastRadius: sigs.path.paths.length > 0 ? sigs.path.paths[0].path : event.cwd,
    privEscalation: sigs.command.wrappers.includes('sudo') || cmd.includes('chmod'),
    sandboxEscape: sigs.network.score > 0.5 && sigs.dlp.has_hit,
    destructive: sigs.command.verbs.some(v => ['rm', 'dd', 'mkfs', 'shred'].includes(v)),
    exfiltration: sigs.dlp.has_hit || (sigs.network.has_data_flag),
  }
}

function BoolCell({ label, value }: { label: string; value: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span className="font-sans text-10 uppercase tracking-wide text-zinc-600 w-28 shrink-0">{label}</span>
      <span className={`font-mono text-12 font-medium ${value ? 'text-deny' : 'text-zinc-500'}`}>
        {value ? 'YES' : 'NO'}
      </span>
    </div>
  )
}

export function RiskAnalysis({ event }: Props) {
  if (event.action === 'allow') return null
  const d = derive(event)
  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-3">Risk Analysis</div>
      <div className="grid grid-cols-2 gap-2">
        <div>
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-1">Threat</div>
          <div className="font-mono text-12 text-zinc-300">{d.threat}</div>
        </div>
        <div>
          <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-1">Blast Radius</div>
          <div className="font-mono text-12 text-zinc-300 truncate">{d.blastRadius}</div>
        </div>
      </div>
      <div className="flex flex-col gap-1.5 mt-3 pt-3 border-t border-border-faint">
        <BoolCell label="Priv Escalation" value={d.privEscalation} />
        <BoolCell label="Destructive" value={d.destructive} />
        <BoolCell label="Exfiltration" value={d.exfiltration} />
        <BoolCell label="Sandbox Escape" value={d.sandboxEscape} />
      </div>
    </div>
  )
}
