import { useEffect, useRef, useState } from 'react'
import { api, FunctionSummary } from '../api/client'
import { useStore } from '../store'

interface Props { projectId: string }

export function FunctionList({ projectId }: Props) {
  const [functions, setFunctions] = useState<FunctionSummary[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const selectFunction = useStore((s) => s.selectFunction)
  const selected = useStore((s) => s.selectedFunction)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setError(null)
      const params: Record<string, string> = {}
      if (search) params.search = search
      api.listFunctions(projectId, params).then((data) => {
        setFunctions(data.functions)
        setTotal(data.total)
      }).catch((e: Error) => setError(e.message))
    }, 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
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
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">
        {total} functions{error && <span className="text-chimera-critical ml-2">Error: {error}</span>}
      </div>
      <div className="flex-1 overflow-y-auto">
        {functions.length === 0 && !error && (
          <div className="px-2 py-4 text-xs text-chimera-muted">
            {search ? 'No functions match your search.' : 'No functions loaded.'}
          </div>
        )}
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
