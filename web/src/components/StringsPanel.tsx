import { useEffect, useMemo, useRef, useState } from 'react'
import { api, StringEntry } from '../api/client'

interface Props { projectId: string }

export function StringsPanel({ projectId }: Props) {
  const [strings, setStrings] = useState<StringEntry[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [minLen, setMinLen] = useState<number | ''>('')
  const [activeSections, setActiveSections] = useState<Set<string>>(new Set())
  const [decodedOnly, setDecodedOnly] = useState(false)
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

  // Sections present in the loaded set — only show chips for actual values.
  const sections = useMemo(() => {
    const s = new Set<string>()
    for (const r of strings) if (r.section) s.add(r.section)
    return Array.from(s).sort()
  }, [strings])

  const filtered = useMemo(() => {
    return strings.filter((s) => {
      if (typeof minLen === 'number' && s.value.length < minLen) return false
      if (activeSections.size > 0 && !(s.section && activeSections.has(s.section))) return false
      if (decodedOnly && !s.decrypted_from) return false
      return true
    })
  }, [strings, minLen, activeSections, decodedOnly])

  function toggleSection(s: string) {
    setActiveSections((prev) => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })
  }

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 space-y-1">
        <input
          type="text"
          placeholder="Search strings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-chimera-bg border border-chimera-border rounded px-2 py-1 text-xs text-chimera-text placeholder-chimera-muted focus:outline-none focus:border-chimera-accent"
        />
        <div className="flex items-center gap-2 text-[10px] text-chimera-muted">
          <label className="flex items-center gap-1">
            min len
            <input
              type="number"
              min={0}
              value={minLen}
              onChange={(e) => setMinLen(e.target.value === '' ? '' : Number(e.target.value))}
              className="w-14 bg-chimera-bg border border-chimera-border rounded px-1 py-0.5 text-chimera-text"
            />
          </label>
          <label className="flex items-center gap-1 cursor-pointer">
            <input
              type="checkbox"
              checked={decodedOnly}
              onChange={(e) => setDecodedOnly(e.target.checked)}
            />
            decoded only
          </label>
        </div>
        {sections.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {sections.map((s) => {
              const on = activeSections.has(s)
              return (
                <button
                  key={s}
                  onClick={() => toggleSection(s)}
                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                    on
                      ? 'bg-chimera-accent text-chimera-bg border-chimera-accent'
                      : 'bg-chimera-surface text-chimera-muted border-chimera-border hover:text-chimera-text'
                  }`}
                >
                  {s}
                </button>
              )
            })}
          </div>
        )}
      </div>
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">
        {filtered.length}/{total} strings
        {error && <span className="text-chimera-critical ml-2">Error: {error}</span>}
      </div>
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && !error && (
          <div className="px-2 py-4 text-xs text-chimera-muted">
            {search || activeSections.size > 0 || decodedOnly || minLen !== ''
              ? 'No strings match your filters.'
              : 'No strings loaded.'}
          </div>
        )}
        {filtered.map((s, i) => (
          <div
            key={`${s.address}-${i}`}
            className="px-2 py-0.5 text-xs font-mono hover:bg-chimera-panel border-b border-chimera-border/30 flex items-baseline gap-2"
          >
            <span className="text-chimera-muted shrink-0 w-20">{s.address}</span>
            {s.section && (
              <span className="text-[10px] text-chimera-muted shrink-0 w-14 truncate" title={s.section}>
                {s.section}
              </span>
            )}
            {s.decrypted_from && (
              <span
                className="text-[10px] text-chimera-low shrink-0"
                title={`decoded from ${s.decrypted_from}`}
              >
                decoded
              </span>
            )}
            <span className="text-chimera-text break-all">
              {s.value.length > 200 ? s.value.slice(0, 200) + '…' : s.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
