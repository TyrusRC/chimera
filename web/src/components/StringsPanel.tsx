import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface Props { projectId: string }

export function StringsPanel({ projectId }: Props) {
  const [strings, setStrings] = useState<any[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)

  useEffect(() => {
    const params: Record<string, string> = {}
    if (search) params.search = search
    api.listStrings(projectId, params).then((data) => {
      setStrings(data.strings)
      setTotal(data.total)
    }).catch(() => {})
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
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">{total} strings</div>
      <div className="flex-1 overflow-y-auto">
        {strings.map((s, i) => (
          <div key={i} className="px-2 py-0.5 text-xs font-mono hover:bg-chimera-panel border-b border-chimera-border/30">
            <span className="text-chimera-muted mr-2">{s.address}</span>
            <span className="text-chimera-text break-all">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
