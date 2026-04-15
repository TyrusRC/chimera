import { useState } from 'react'
import { Sidebar } from './Sidebar'
import { StatusBar } from './StatusBar'
import { TabBar, TabId } from './TabBar'
import { AnalysisProgress } from '../AnalysisProgress'
import { CodeView } from '../CodeView'
import { FindingsPanel } from '../FindingsPanel'
import { CallGraph } from '../CallGraph'
import { DisassemblyView } from '../DisassemblyView'
import { XrefsPanel } from '../XrefsPanel'
import { ProtectionReport } from '../ProtectionReport'
import { DevicePanel } from '../device/DevicePanel'
import { NetworkPanel } from '../NetworkPanel'
import { useStore } from '../../store'

interface Props { projectId: string }

export function MainLayout({ projectId }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>('code')
  const selectedFunction = useStore((s) => s.selectedFunction)

  return (
    <div className="flex flex-col h-screen bg-chimera-bg">
      {/* Top bar */}
      <div className="h-10 bg-chimera-surface border-b border-chimera-border flex items-center px-4 text-sm">
        <span className="text-chimera-accent font-bold mr-2">CHIMERA</span>
        <span className="text-chimera-muted">Mobile RE Platform</span>
        <button
          onClick={() => useStore.getState().setProject(null)}
          className="ml-auto text-chimera-muted hover:text-chimera-text text-xs"
        >
          Switch Project
        </button>
      </div>

      <AnalysisProgress projectId={projectId} />

      <div className="flex flex-1 overflow-hidden">
        {/* Left sidebar */}
        <Sidebar projectId={projectId} />

        {/* Main content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <TabBar activeTab={activeTab} onTabChange={setActiveTab} />
          <div className="flex-1 flex overflow-hidden">
            {/* Primary tab area */}
            <div className="flex-1 overflow-hidden">
              {activeTab === 'code' && (
                <CodeView projectId={projectId} address={selectedFunction} />
              )}
              {activeTab === 'findings' && (
                <FindingsPanel projectId={projectId} />
              )}
              {activeTab === 'callgraph' && (
                <CallGraph projectId={projectId} address={selectedFunction} />
              )}
              {activeTab === 'disassembly' && (
                <DisassemblyView projectId={projectId} address={selectedFunction} />
              )}
              {activeTab === 'protection' && (
                <ProtectionReport projectId={projectId} />
              )}
              {activeTab === 'devices' && (
                <DevicePanel />
              )}
              {activeTab === 'network' && (
                <NetworkPanel projectId={projectId} />
              )}
            </div>

            {/* Right panel — cross-references */}
            {selectedFunction && activeTab !== 'findings' && activeTab !== 'protection' && activeTab !== 'devices' && activeTab !== 'network' && (
              <>
                <div className="w-px bg-chimera-border" />
                <div className="w-56 flex flex-col overflow-hidden bg-chimera-surface border-l border-chimera-border">
                  <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-chimera-muted border-b border-chimera-border">
                    Cross-References
                  </div>
                  <XrefsPanel projectId={projectId} address={selectedFunction} />
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <StatusBar projectId={projectId} />
    </div>
  )
}
