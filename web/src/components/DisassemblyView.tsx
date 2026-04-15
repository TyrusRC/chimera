import { useEffect, useState } from 'react'
import { api, Instruction } from '../api/client'

interface Props {
  projectId: string
  address: string | null
}

export function DisassemblyView({ projectId, address }: Props) {
  const [instructions, setInstructions] = useState<Instruction[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!address) {
      setInstructions([])
      setError(null)
      return
    }
    setError(null)
    api.getDisassembly(projectId, address)
      .then((d) => setInstructions(d.instructions ?? []))
      .catch((e: Error) => setError(e.message))
  }, [projectId, address])

  if (!address) {
    return (
      <div className="p-4 text-chimera-muted text-xs font-mono">
        Select a function to view disassembly
      </div>
    )
  }

  if (error || instructions.length === 0) {
    return (
      <div className="p-4 text-xs font-mono">
        <div className="text-chimera-accent mb-2">Disassembly for {address}</div>
        <div className="text-chimera-muted">
          Disassembly view requires r2/Ghidra backend data.
          <br />
          Use the Decompiled Code tab for source-level analysis.
        </div>
      </div>
    )
  }

  return (
    <div className="h-full overflow-auto bg-chimera-bg">
      <div className="px-2 py-1 bg-chimera-surface border-b border-chimera-border text-xs text-chimera-muted">
        Disassembly — {address}
      </div>
      <table className="w-full text-xs font-mono">
        <tbody>
          {instructions.map((ins) => (
            <tr
              key={ins.address}
              className="hover:bg-chimera-panel border-b border-chimera-border/20"
            >
              <td className="px-2 py-0.5 text-chimera-muted w-24 select-none">
                {ins.address}
              </td>
              <td className="px-2 py-0.5 text-chimera-muted w-24 select-none">
                {ins.bytes}
              </td>
              <td className="px-2 py-0.5 text-chimera-accent w-20">{ins.mnemonic}</td>
              <td className="px-2 py-0.5 text-chimera-text">{ins.operands}</td>
              {ins.comment && (
                <td className="px-2 py-0.5 text-chimera-muted italic">
                  ; {ins.comment}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
