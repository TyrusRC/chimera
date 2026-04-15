import { useEffect, useState } from 'react'
import { api, FunctionDetail } from '../api/client'
import { useStore } from '../store'

interface Props {
  projectId: string
  address: string | null
}

export function XrefsPanel({ projectId, address }: Props) {
  const [func, setFunc] = useState<FunctionDetail | null>(null)
  const selectFunction = useStore((s) => s.selectFunction)

  useEffect(() => {
    if (!address) {
      setFunc(null)
      return
    }
    api
      .getFunction(projectId, address)
      .then(setFunc)
      .catch(() => setFunc(null))
  }, [projectId, address])

  if (!func) {
    return (
      <div className="p-2 text-xs text-chimera-muted">Select a function</div>
    )
  }

  const callers = func.callers ?? []
  const callees = func.callees ?? []

  return (
    <div className="p-2 text-xs overflow-y-auto h-full">
      <div className="mb-3">
        <div className="text-chimera-muted mb-1 font-semibold uppercase tracking-wide text-[10px]">
          Callers ({callers.length})
        </div>
        {callers.length === 0 && (
          <div className="text-chimera-muted italic px-1">none</div>
        )}
        {callers.map((c) => (
          <button
            key={c.address}
            onClick={() => selectFunction(c.address)}
            className="block w-full text-left px-1 py-0.5 hover:bg-chimera-panel text-chimera-accent font-mono truncate"
            title={`${c.address}  ${c.name}`}
          >
            {c.address} <span className="text-chimera-text">{c.name}</span>
          </button>
        ))}
      </div>

      <div>
        <div className="text-chimera-muted mb-1 font-semibold uppercase tracking-wide text-[10px]">
          Callees ({callees.length})
        </div>
        {callees.length === 0 && (
          <div className="text-chimera-muted italic px-1">none</div>
        )}
        {callees.map((c) => (
          <button
            key={c.address}
            onClick={() => selectFunction(c.address)}
            className="block w-full text-left px-1 py-0.5 hover:bg-chimera-panel text-chimera-accent font-mono truncate"
            title={`${c.address}  ${c.name}`}
          >
            {c.address} <span className="text-chimera-text">{c.name}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
