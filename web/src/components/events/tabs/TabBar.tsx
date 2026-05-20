interface Tab { id: string; label: string }

interface Props {
  tabs: Tab[]
  activeTab: string
  onSelect: (id: string) => void
}

export function TabBar({ tabs, activeTab, onSelect }: Props) {
  return (
    <div className="flex border-b border-border shrink-0">
      {tabs.map(tab => (
        <button
          key={tab.id}
          onClick={() => onSelect(tab.id)}
          className={`px-4 py-2 text-12 font-sans transition-colors border-b-2 -mb-px ${
            activeTab === tab.id
              ? 'border-phase1 text-zinc-100'
              : 'border-transparent text-zinc-500 hover:text-zinc-300'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}
