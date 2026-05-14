import { useEffect, useState } from 'react'
import { Sidebar } from './Sidebar'
import { StatusBar } from './StatusBar'
import { TabBar, TabId } from './TabBar'
import { AnalysisProgress } from '../AnalysisProgress'
import { CodeView } from '../CodeView'
import { FindingsPanel } from '../FindingsPanel'
import { CallGraph } from '../CallGraph'
import { DisassemblyView } from '../DisassemblyView'
import { HexView } from '../HexView'
import { DiffPanel } from '../DiffPanel'
import { XrefsPanel } from '../XrefsPanel'
import { ProtectionReport } from '../ProtectionReport'
import { DevicePanel } from '../device/DevicePanel'
import { NetworkPanel } from '../NetworkPanel'
import { api, ProjectCapabilities } from '../../api/client'
import { useStore } from '../../store'

interface Props { projectId: string }

export function MainLayout({ projectId }: Props) {
  const [activeTab, setActiveTab] = useState<TabId>('code')
  const [capabilities, setCapabilities] = useState<ProjectCapabilities | undefined>(undefined)
  const selectedFunction = useStore((s) => s.selectedFunction)

  // Fetch project detail to discover which analyst surfaces apply.
  useEffect(() => {
    const ac = new AbortController()
    api.getProject(projectId)
      .then((p) => { if (!ac.signal.aborted) setCapabilities(p.capabilities) })
      .catch(() => { /* leave undefined → permissive */ })
    return () => ac.abort()
  }, [projectId])

  // If the currently-active tab becomes hidden by capabilities, snap back to 'code'.
  useEffect(() => {
    if (!capabilities) return
    const hidden = (
      (activeTab === 'protection' && !capabilities.masvs) ||
      (activeTab === 'devices' && !capabilities.frida) ||
      (activeTab === 'network' && !capabilities.network_security_config)
    )
    if (hidden) setActiveTab('code')
  }, [capabilities, activeTab])

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
          <TabBar activeTab={activeTab} onTabChange={setActiveTab} capabilities={capabilities} />
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
              {activeTab === 'hex' && (
                <HexView projectId={projectId} />
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
              {activeTab === 'diff' && (
                <DiffPanel currentProjectId={projectId} />
              )}
            </div>

            {/* Right panel — cross-references */}
            {selectedFunction && activeTab !== 'findings' && activeTab !== 'protection' && activeTab !== 'devices' && activeTab !== 'network' && activeTab !== 'hex' && activeTab !== 'diff' && (
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
