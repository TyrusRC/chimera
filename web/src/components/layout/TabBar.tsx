import { ProjectCapabilities } from '../../api/client'

export type TabId = 'code' | 'findings' | 'callgraph' | 'hex' | 'disassembly' | 'protection' | 'devices' | 'network'

interface Props {
  activeTab: TabId
  onTabChange: (tab: TabId) => void
  capabilities?: ProjectCapabilities
}

interface TabDef {
  id: TabId
  label: string
  /** Capability key required to render this tab. Tabs without a key are always shown. */
  requires?: keyof ProjectCapabilities
}

const TABS: TabDef[] = [
  { id: 'code', label: 'Decompiled Code' },
  { id: 'findings', label: 'Findings' },
  { id: 'callgraph', label: 'Call Graph' },
  { id: 'disassembly', label: 'Disassembly' },
  { id: 'hex', label: 'Hex' },
  { id: 'protection', label: 'Protection Report', requires: 'masvs' },
  { id: 'devices', label: 'Devices', requires: 'frida' },
  { id: 'network', label: 'Network', requires: 'network_security_config' },
]

function isVisible(tab: TabDef, caps?: ProjectCapabilities): boolean {
  if (!tab.requires) return true
  if (!caps) return true  // unknown capabilities → permissive (don't hide tabs prematurely)
  return caps[tab.requires]
}

export function TabBar({ activeTab, onTabChange, capabilities }: Props) {
  const visible = TABS.filter((t) => isVisible(t, capabilities))
  return (
    <div className="flex bg-chimera-surface border-b border-chimera-border overflow-x-auto">
      {visible.map((t) => (
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
