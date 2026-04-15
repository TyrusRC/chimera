import { useState } from 'react'

interface Props {
  data?: Uint8Array
}

export function HexView({ data }: Props) {
  const [offset, setOffset] = useState(0)
  const PAGE = 256 // rows × 16 bytes

  if (!data || data.length === 0) {
    return (
      <div className="p-4 text-chimera-muted text-xs">
        No binary data loaded
      </div>
    )
  }

  const start = offset * 16
  const end = Math.min(start + PAGE * 16, data.length)
  const rows: string[] = []

  for (let i = start; i < end; i += 16) {
    const addr = i.toString(16).padStart(8, '0')
    const hex: string[] = []
    const ascii: string[] = []
    for (let j = 0; j < 16; j++) {
      if (i + j < data.length) {
        hex.push(data[i + j].toString(16).padStart(2, '0'))
        const ch = data[i + j]
        ascii.push(ch >= 32 && ch < 127 ? String.fromCharCode(ch) : '.')
      } else {
        hex.push('  ')
        ascii.push(' ')
      }
    }
    rows.push(
      `${addr}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`
    )
  }

  const totalPages = Math.ceil(data.length / (PAGE * 16))
  const currentPage = Math.floor(offset / PAGE)

  return (
    <div className="flex flex-col h-full bg-chimera-bg">
      <div className="flex items-center px-2 py-1 bg-chimera-surface border-b border-chimera-border text-xs text-chimera-muted gap-4">
        <span>
          {data.length.toLocaleString()} bytes
        </span>
        {totalPages > 1 && (
          <span className="flex items-center gap-2">
            <button
              disabled={currentPage === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE))}
              className="px-1 hover:text-chimera-text disabled:opacity-30"
            >
              ◀
            </button>
            page {currentPage + 1} / {totalPages}
            <button
              disabled={currentPage >= totalPages - 1}
              onClick={() => setOffset(offset + PAGE)}
              className="px-1 hover:text-chimera-text disabled:opacity-30"
            >
              ▶
            </button>
          </span>
        )}
      </div>
      <pre className="flex-1 p-2 text-xs font-mono text-chimera-text overflow-auto leading-5">
        {rows.join('\n')}
      </pre>
    </div>
  )
}
