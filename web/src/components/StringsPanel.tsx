import { useEffect, useRef, useState } from 'react'
import { api, StringEntry } from '../api/client'

interface Props { projectId: string }

export function StringsPanel({ projectId }: Props) {
  const [strings, setStrings] = useState<StringEntry[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      setError(null)
      const params: Record<string, string> = {}
      if (search) params.search = search
      api.listStrings(projectId, params).then((data) => {
        setStrings(data.strings)
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
          placeholder="Search strings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-chimera-bg border border-chimera-border rounded px-2 py-1 text-xs text-chimera-text placeholder-chimera-muted focus:outline-none focus:border-chimera-accent"
        />
      </div>
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">
        {total} strings{error && <span className="text-chimera-critical ml-2">Error: {error}</span>}
      </div>
      <div className="flex-1 overflow-y-auto">
        {strings.length === 0 && !error && (
          <div className="px-2 py-4 text-xs text-chimera-muted">
            {search ? 'No strings match your search.' : 'No strings loaded.'}
          </div>
        )}
        {strings.map((s, i) => (
          <div key={`${s.address}-${i}`} className="px-2 py-0.5 text-xs font-mono hover:bg-chimera-panel border-b border-chimera-border/30">
            <span className="text-chimera-muted mr-2">{s.address}</span>
            <span className="text-chimera-text break-all">{s.value.length > 200 ? s.value.slice(0, 200) + '…' : s.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
