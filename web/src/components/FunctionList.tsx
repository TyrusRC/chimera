import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { useStore } from '../store'

interface Props { projectId: string }

export function FunctionList({ projectId }: Props) {
  const [functions, setFunctions] = useState<any[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)
  const selectFunction = useStore((s) => s.selectFunction)
  const selected = useStore((s) => s.selectedFunction)

  useEffect(() => {
    const params: Record<string, string> = {}
    if (search) params.search = search
    api.listFunctions(projectId, params).then((data) => {
      setFunctions(data.functions)
      setTotal(data.total)
    }).catch(() => {})
  }, [projectId, search])

  return (
    <div className="flex flex-col h-full">
      <div className="p-2">
        <input
          type="text"
          placeholder="Search functions..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-chimera-bg border border-chimera-border rounded px-2 py-1 text-xs text-chimera-text placeholder-chimera-muted focus:outline-none focus:border-chimera-accent"
        />
      </div>
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">{total} functions</div>
      <div className="flex-1 overflow-y-auto">
        {functions.map((f) => (
          <button
            key={f.address}
            onClick={() => selectFunction(f.address)}
            className={`w-full text-left px-2 py-1 text-xs font-mono hover:bg-chimera-panel ${
              selected === f.address ? 'bg-chimera-panel text-chimera-accent' : 'text-chimera-text'
            }`}
          >
            <span className="text-chimera-muted mr-1">{f.address}</span>
            <span>{f.name}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
