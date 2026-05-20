import { useState } from 'react'
import type { AegisEvent } from '../../lib/types'
import { Toast } from '../shared/Toast'

interface Props { event: AegisEvent }

export function RemediationPanel({ event }: Props) {
  const [toast, setToast] = useState('')
  const [toastVisible, setToastVisible] = useState(false)

  if (event.action === 'allow') return null

  const showToast = (msg: string) => {
    setToast(msg)
    setToastVisible(true)
    setTimeout(() => setToastVisible(false), 1500)
  }

  const copyJSON = () => {
    navigator.clipboard?.writeText(JSON.stringify(event, null, 2))
    showToast('Event JSON copied')
  }

  const generateAllowlistYAML = () => {
    const yaml = `commands:\n  - "${event.raw_command}"\n# Rule: ${event.rule}\n# Added: ${new Date().toISOString()}`
    navigator.clipboard?.writeText(yaml)
    showToast('Allowlist YAML copied')
  }

  const handleSimulate = () => {
    window.location.hash = `#/policies?cmd=${encodeURIComponent(event.raw_command)}`
  }

  const copyAsCurl = () => {
    const curl = `curl -X POST http://localhost:8080/api/evaluate \\
  -H 'Content-Type: application/json' \\
  -d '${JSON.stringify({ tool: event.tool, command: event.raw_command, cwd: event.cwd })}'`
    navigator.clipboard?.writeText(curl)
    showToast('curl command copied')
  }

  return (
    <div className="border border-border rounded p-3 bg-panel">
      <div className="text-10 font-sans uppercase tracking-wide text-zinc-600 mb-2">Remediation</div>
      <div className="flex gap-2 flex-wrap">
        <button
          onClick={generateAllowlistYAML}
          className="px-3 py-1.5 text-12 font-sans bg-raised border border-border rounded hover:border-border-strong text-zinc-300 transition-colors"
        >
          Add to Allowlist
        </button>
        <button
          onClick={copyJSON}
          className="px-3 py-1.5 text-12 font-sans bg-raised border border-border rounded hover:border-border-strong text-zinc-300 transition-colors"
        >
          Copy JSON
        </button>
        <button
          onClick={handleSimulate}
          className="px-3 py-1.5 text-12 font-sans bg-raised border border-border rounded hover:border-border-strong text-zinc-300 transition-colors"
        >
          Simulate
        </button>
        <button
          onClick={copyAsCurl}
          className="px-3 py-1.5 text-12 font-sans bg-raised border border-border rounded hover:border-border-strong text-zinc-300 transition-colors"
        >
          Copy as curl
        </button>
      </div>
      <Toast message={toast} visible={toastVisible} />
    </div>
  )
}
