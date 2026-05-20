import { useState } from 'react'
import { useEventsStore } from '../../stores/events'
import { DetailHeader } from './DetailHeader'
import { TabBar } from './tabs/TabBar'
import { SummaryTab } from './tabs/SummaryTab'
import { TraceTab } from './tabs/TraceTab'
import { SignalsTab } from './tabs/SignalsTab'
import { PolicyTab } from './tabs/PolicyTab'
import { ContextTab } from './tabs/ContextTab'
import { RelatedTab } from './tabs/RelatedTab'

const TABS = [
  { id: 'summary', label: 'Summary' },
  { id: 'trace', label: 'Trace' },
  { id: 'signals', label: 'Signals' },
  { id: 'policy', label: 'Policy' },
  { id: 'context', label: 'Context' },
  { id: 'related', label: 'Related' },
]

const AMBIENT: Record<string, string> = {
  deny: 'bg-deny/[0.03]',
  allow: 'bg-allow/[0.03]',
  escalate: 'bg-escalate/[0.03]',
}

export function EventDetail() {
  const { events, selectedId } = useEventsStore()
  const [activeTab, setActiveTab] = useState('summary')
  const event = events.find(e => e.id === selectedId)

  if (!event) return null

  return (
    <div className={`flex flex-col h-full overflow-hidden ${AMBIENT[event.action]}`}>
      <DetailHeader event={event} />
      <TabBar tabs={TABS} activeTab={activeTab} onSelect={setActiveTab} />
      {activeTab === 'summary' && <SummaryTab event={event} />}
      {activeTab === 'trace' && <TraceTab event={event} />}
      {activeTab === 'signals' && <SignalsTab event={event} />}
      {activeTab === 'policy' && <PolicyTab event={event} />}
      {activeTab === 'context' && <ContextTab event={event} />}
      {activeTab === 'related' && <RelatedTab event={event} />}
    </div>
  )
}
