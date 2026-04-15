export type TabId = 'code' | 'findings' | 'callgraph' | 'hex' | 'disassembly' | 'protection' | 'devices' | 'network'

interface Props {
  activeTab: TabId
  onTabChange: (tab: TabId) => void
}

const TABS: { id: TabId; label: string }[] = [
  { id: 'code', label: 'Decompiled Code' },
  { id: 'findings', label: 'Findings' },
  { id: 'callgraph', label: 'Call Graph' },
  { id: 'disassembly', label: 'Disassembly' },
  { id: 'protection', label: 'Protection Report' },
  { id: 'devices', label: 'Devices' },
  { id: 'network', label: 'Network' },
]

export function TabBar({ activeTab, onTabChange }: Props) {
  return (
    <div className="flex bg-chimera-surface border-b border-chimera-border overflow-x-auto">
      {TABS.map((t) => (
        <button
          key={t.id}
          onClick={() => onTabChange(t.id)}
          className={`px-4 py-2 text-xs font-medium border-b-2 whitespace-nowrap ${
            activeTab === t.id
              ? 'text-chimera-accent border-chimera-accent bg-chimera-bg'
              : 'text-chimera-muted border-transparent hover:text-chimera-text'
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}
