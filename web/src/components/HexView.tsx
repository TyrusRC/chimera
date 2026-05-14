import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface Props {
  projectId: string
}

const PAGE_SIZE = 4096 // bytes per page (256 rows × 16 bytes)
const ROW_WIDTH = 16

export function HexView({ projectId }: Props) {
  const [offset, setOffset] = useState(0)
  const [hex, setHex] = useState<string>('')
  const [totalSize, setTotalSize] = useState<number>(0)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    api.getBytes(projectId, offset, PAGE_SIZE, ac.signal)
      .then((r) => {
        if (ac.signal.aborted) return
        setHex(r.hex)
        setTotalSize(r.total_size)
      })
      .catch((e) => {
        if (ac.signal.aborted) return
        setError(e?.message || 'Failed to load bytes')
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false)
      })
    return () => ac.abort()
  }, [projectId, offset])

  // Convert hex string ("0a1b2c…") into Uint8Array for rendering.
  const bytes = hexToBytes(hex)

  const rows: string[] = []
  for (let i = 0; i < bytes.length; i += ROW_WIDTH) {
    const addr = (offset + i).toString(16).padStart(8, '0')
    const hexCols: string[] = []
    const ascii: string[] = []
    for (let j = 0; j < ROW_WIDTH; j++) {
      if (i + j < bytes.length) {
        hexCols.push(bytes[i + j].toString(16).padStart(2, '0'))
        const ch = bytes[i + j]
        ascii.push(ch >= 32 && ch < 127 ? String.fromCharCode(ch) : '.')
      } else {
        hexCols.push('  ')
        ascii.push(' ')
      }
    }
    rows.push(
      `${addr}  ${hexCols.slice(0, 8).join(' ')}  ${hexCols.slice(8).join(' ')}  |${ascii.join('')}|`,
    )
  }

  const canPrev = offset > 0
  const canNext = offset + PAGE_SIZE < totalSize
  const pageNum = Math.floor(offset / PAGE_SIZE) + 1
  const totalPages = Math.max(1, Math.ceil(totalSize / PAGE_SIZE))

  return (
    <div className="flex flex-col h-full bg-chimera-bg">
      <div className="flex items-center px-2 py-1 bg-chimera-surface border-b border-chimera-border text-xs text-chimera-muted gap-4">
        <span>{totalSize.toLocaleString()} bytes</span>
        <span className="flex items-center gap-2">
          <button
            disabled={!canPrev}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            className="px-1 hover:text-chimera-text disabled:opacity-30"
            title="Previous page"
          >
            ◀
          </button>
          <span>
            page {pageNum} / {totalPages}
          </span>
          <button
            disabled={!canNext}
            onClick={() => setOffset(offset + PAGE_SIZE)}
            className="px-1 hover:text-chimera-text disabled:opacity-30"
            title="Next page"
          >
            ▶
          </button>
        </span>
        <span className="ml-auto">
          {loading && <span className="text-chimera-muted">loading…</span>}
          {error && <span className="text-red-500">{error}</span>}
        </span>
      </div>
      <pre className="flex-1 p-2 text-xs font-mono text-chimera-text overflow-auto leading-5">
        {rows.length > 0 ? rows.join('\n') : (loading ? '' : 'No data')}
      </pre>
    </div>
  )
}

function hexToBytes(hex: string): Uint8Array {
  if (!hex) return new Uint8Array(0)
  const n = Math.floor(hex.length / 2)
  const out = new Uint8Array(n)
  for (let i = 0; i < n; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return out
}
