import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { api, FunctionSummary } from '../api/client'
import { useStore } from '../store'

interface Props { projectId: string }

const ROW_HEIGHT = 24
const OVERSCAN = 8

export function FunctionList({ projectId }: Props) {
  const [functions, setFunctions] = useState<FunctionSummary[]>([])
  const [search, setSearch] = useState('')
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [activeClasses, setActiveClasses] = useState<Set<string>>(new Set())
  const selectFunction = useStore((s) => s.selectFunction)
  const selected = useStore((s) => s.selectedFunction)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const scrollRef = useRef<HTMLDivElement | null>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportH, setViewportH] = useState(0)

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

  // Track viewport height so the windowing math knows how many rows fit.
  useLayoutEffect(() => {
    if (!scrollRef.current) return
    const el = scrollRef.current
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight))
    ro.observe(el)
    setViewportH(el.clientHeight)
    return () => ro.disconnect()
  }, [])

  // Classification chips: collect from the loaded set, build a sorted unique list.
  const classifications = useMemo(() => {
    const s = new Set<string>()
    for (const f of functions) if (f.classification) s.add(f.classification)
    return Array.from(s).sort()
  }, [functions])

  const filtered = useMemo(() => {
    if (activeClasses.size === 0) return functions
    return functions.filter((f) => activeClasses.has(f.classification))
  }, [functions, activeClasses])

  const visibleCount = Math.ceil(viewportH / ROW_HEIGHT) + OVERSCAN * 2
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const endIdx = Math.min(filtered.length, startIdx + visibleCount)
  const slice = filtered.slice(startIdx, endIdx)
  const topPad = startIdx * ROW_HEIGHT
  const bottomPad = Math.max(0, (filtered.length - endIdx) * ROW_HEIGHT)

  function toggleClass(c: string) {
    setActiveClasses((prev) => {
      const next = new Set(prev)
      if (next.has(c)) next.delete(c)
      else next.add(c)
      return next
    })
  }

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
      {classifications.length > 0 && (
        <div className="px-2 pb-1 flex flex-wrap gap-1">
          {classifications.map((c) => {
            const on = activeClasses.has(c)
            return (
              <button
                key={c}
                onClick={() => toggleClass(c)}
                className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                  on
                    ? 'bg-chimera-accent text-chimera-bg border-chimera-accent'
                    : 'bg-chimera-surface text-chimera-muted border-chimera-border hover:text-chimera-text'
                }`}
              >
                {c}
              </button>
            )
          })}
        </div>
      )}
      <div className="px-2 pb-1 text-[10px] text-chimera-muted">
        {filtered.length}/{total} functions
        {error && <span className="text-chimera-critical ml-2">Error: {error}</span>}
      </div>
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto"
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        {filtered.length === 0 && !error && (
          <div className="px-2 py-4 text-xs text-chimera-muted">
            {search || activeClasses.size > 0 ? 'No functions match your filters.' : 'No functions loaded.'}
          </div>
        )}
        {filtered.length > 0 && (
          <>
            <div style={{ height: topPad }} />
            {slice.map((f) => (
              <button
                key={f.address}
                onClick={() => selectFunction(f.address)}
                style={{ height: ROW_HEIGHT }}
                className={`w-full text-left px-2 text-xs font-mono hover:bg-chimera-panel truncate ${
                  selected === f.address ? 'bg-chimera-panel text-chimera-accent' : 'text-chimera-text'
                }`}
                title={`${f.address}  ${f.name}  [${f.classification}]`}
              >
                <span className="text-chimera-muted mr-1">{f.address}</span>
                <span>{f.name}</span>
              </button>
            ))}
            <div style={{ height: bottomPad }} />
          </>
        )}
      </div>
    </div>
  )
}
