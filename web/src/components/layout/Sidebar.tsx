import { useStore } from '../../store'
import { FunctionList } from '../FunctionList'
import { StringsPanel } from '../StringsPanel'

interface Props { projectId: string }

export function Sidebar({ projectId }: Props) {
  const tab = useStore((s) => s.sidebarTab)
  const setTab = useStore((s) => s.setSidebarTab)

  return (
    <div className="w-72 bg-chimera-surface border-r border-chimera-border flex flex-col">
      <div className="flex border-b border-chimera-border">
        <button
          onClick={() => setTab('functions')}
          className={`flex-1 px-3 py-2 text-xs font-medium ${
            tab === 'functions' ? 'text-chimera-accent border-b-2 border-chimera-accent' : 'text-chimera-muted'
          }`}
        >
          Functions
        </button>
        <button
          onClick={() => setTab('strings')}
          className={`flex-1 px-3 py-2 text-xs font-medium ${
            tab === 'strings' ? 'text-chimera-accent border-b-2 border-chimera-accent' : 'text-chimera-muted'
          }`}
        >
          Strings
        </button>
      </div>
      <div className="flex-1 overflow-hidden">
        {tab === 'functions' && <FunctionList projectId={projectId} />}
        {tab === 'strings' && <StringsPanel projectId={projectId} />}
      </div>
    </div>
  )
}
