import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface Props { projectId: string }

const severityColors: Record<string, string> = {
  critical: 'bg-chimera-critical text-white',
  high: 'bg-chimera-high text-black',
  medium: 'bg-chimera-medium text-black',
  low: 'bg-chimera-low text-black',
  info: 'bg-chimera-muted text-white',
}

export function FindingsPanel({ projectId }: Props) {
  const [findings, setFindings] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)
  const [total, setTotal] = useState(0)

  useEffect(() => {
    api.listFindings(projectId).then((data) => {
      setFindings(data.findings)
      setTotal(data.total)
    }).catch(() => {})
  }, [projectId])

  return (
    <div className="flex h-full">
      <div className="w-1/2 overflow-y-auto border-r border-chimera-border">
        <div className="px-3 py-2 text-xs text-chimera-muted border-b border-chimera-border">
          {total} findings
        </div>
        {findings.map((f, i) => (
          <button
            key={i}
            onClick={() => setSelected(f)}
            className={`w-full text-left px-3 py-2 text-xs border-b border-chimera-border/30 hover:bg-chimera-panel ${
              selected === f ? 'bg-chimera-panel' : ''
            }`}
          >
            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold mr-2 ${severityColors[f.severity] || ''}`}>
              {f.severity?.toUpperCase()}
            </span>
            <span className="text-chimera-muted mr-1">{f.rule_id}</span>
            <span className="text-chimera-text">{f.title}</span>
          </button>
        ))}
      </div>
      <div className="w-1/2 overflow-y-auto p-4">
        {selected ? (
          <div className="text-xs">
            <h3 className="text-sm font-bold text-chimera-text mb-2">{selected.title}</h3>
            <div className="space-y-2 text-chimera-text">
              <div><span className="text-chimera-muted">Rule:</span> {selected.rule_id}</div>
              <div><span className="text-chimera-muted">Severity:</span> {selected.severity}</div>
              <div><span className="text-chimera-muted">MASVS:</span> {selected.masvs_category || 'N/A'}</div>
              <div><span className="text-chimera-muted">Location:</span> <code className="text-chimera-accent">{selected.location}</code></div>
              <div className="mt-3">{selected.description}</div>
              {selected.evidence_static && (
                <div className="mt-3">
                  <div className="text-chimera-muted mb-1">Evidence:</div>
                  <pre className="bg-chimera-bg p-2 rounded text-chimera-text overflow-x-auto">{selected.evidence_static}</pre>
                </div>
              )}
              {selected.business_impact && (
                <div className="mt-2 text-chimera-high">Impact: {selected.business_impact}</div>
              )}
            </div>
          </div>
        ) : (
          <div className="text-chimera-muted text-xs">Select a finding to view details</div>
        )}
      </div>
    </div>
  )
}
