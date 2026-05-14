import { useEffect, useState } from 'react'
import { api, DiffResult, ProjectSummary } from '../api/client'

interface Props {
  currentProjectId: string
}

export function DiffPanel({ currentProjectId }: Props) {
  const [projects, setProjects] = useState<ProjectSummary[]>([])
  const [other, setOther] = useState<string>('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<DiffResult | null>(null)

  useEffect(() => {
    const ac = new AbortController()
    api.listProjects()
      .then((ps) => { if (!ac.signal.aborted) setProjects(ps) })
      .catch((e: Error) => { if (!ac.signal.aborted) setError(e.message) })
    return () => ac.abort()
  }, [])

  async function runDiff() {
    if (!other) {
      setError('pick a project to compare against')
      return
    }
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const r = await api.diffProjects(currentProjectId, other)
      setResult(r)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const candidates = projects.filter((p) => p.id !== currentProjectId)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="p-3 border-b border-chimera-border flex flex-wrap items-center gap-2 text-xs">
        <span className="text-chimera-muted">Compare</span>
        <code className="text-chimera-accent">{currentProjectId}</code>
        <span className="text-chimera-muted">→</span>
        <select
          value={other}
          onChange={(e) => setOther(e.target.value)}
          className="bg-chimera-surface text-chimera-text border border-chimera-border rounded px-2 py-1 font-mono"
        >
          <option value="">-- pick project --</option>
          {candidates.map((p) => (
            <option key={p.id} value={p.id}>{p.name} ({p.id})</option>
          ))}
        </select>
        <button
          onClick={runDiff}
          disabled={busy || !other}
          className="bg-chimera-accent text-chimera-bg px-3 py-1 rounded disabled:opacity-50"
        >
          {busy ? 'Comparing…' : 'Compare'}
        </button>
        {error && <span className="text-chimera-critical">{error}</span>}
      </div>

      <div className="flex-1 overflow-y-auto p-3 text-xs">
        {!result && !busy && (
          <div className="text-chimera-muted">Pick another project and hit Compare.</div>
        )}
        {result && <DiffResultView result={result} />}
      </div>
    </div>
  )
}

function DiffResultView({ result }: { result: DiffResult }) {
  return (
    <div className="space-y-4">
      <section>
        <h3 className="text-chimera-accent font-semibold mb-1">
          Findings added ({result.findings_added.length})
        </h3>
        {result.findings_added.length === 0 ? (
          <div className="text-chimera-muted italic">none</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-chimera-muted">
                <th className="text-left px-1">Rule</th>
                <th className="text-left px-1">Severity</th>
                <th className="text-left px-1">Title</th>
              </tr>
            </thead>
            <tbody>
              {result.findings_added.map((f, i) => (
                <tr key={i} className="border-b border-chimera-border/30">
                  <td className="px-1"><code>{f.finding_id}</code></td>
                  <td className="px-1">{f.severity}</td>
                  <td className="px-1 text-chimera-text">{f.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h3 className="text-chimera-low font-semibold mb-1">
          Findings resolved ({result.findings_resolved.length})
        </h3>
        {result.findings_resolved.length === 0 ? (
          <div className="text-chimera-muted italic">none</div>
        ) : (
          <table className="w-full text-xs font-mono">
            <tbody>
              {result.findings_resolved.map((f, i) => (
                <tr key={i} className="border-b border-chimera-border/30">
                  <td className="px-1"><code>{f.finding_id}</code></td>
                  <td className="px-1">{f.severity}</td>
                  <td className="px-1 text-chimera-text">{f.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {(result.permissions_added.length > 0 || result.permissions_removed.length > 0) && (
        <section>
          <h3 className="font-semibold mb-1">Permissions</h3>
          <div className="flex gap-4">
            <div className="flex-1">
              <div className="text-chimera-accent">added ({result.permissions_added.length})</div>
              <ul className="list-disc pl-5">
                {result.permissions_added.map((p) => <li key={p}><code>{p}</code></li>)}
              </ul>
            </div>
            <div className="flex-1">
              <div className="text-chimera-low">removed ({result.permissions_removed.length})</div>
              <ul className="list-disc pl-5">
                {result.permissions_removed.map((p) => <li key={p}><code>{p}</code></li>)}
              </ul>
            </div>
          </div>
        </section>
      )}

      {(result.exported_added.length > 0 || result.exported_removed.length > 0) && (
        <section>
          <h3 className="font-semibold mb-1">Exported components</h3>
          <div className="flex gap-4">
            <div className="flex-1">
              <div className="text-chimera-accent">added</div>
              <ul className="list-disc pl-5">
                {result.exported_added.map((c, i) => (
                  <li key={i}>{c.kind} <code>{c.name}</code></li>
                ))}
              </ul>
            </div>
            <div className="flex-1">
              <div className="text-chimera-low">removed</div>
              <ul className="list-disc pl-5">
                {result.exported_removed.map((c, i) => (
                  <li key={i}>{c.kind} <code>{c.name}</code></li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {(result.sdks_added.length > 0 || result.sdks_removed.length > 0) && (
        <section>
          <h3 className="font-semibold mb-1">SDKs</h3>
          <div className="flex gap-4">
            <div className="flex-1">
              <div className="text-chimera-accent">added</div>
              <ul className="list-disc pl-5">
                {result.sdks_added.map((s) => <li key={s}><code>{s}</code></li>)}
              </ul>
            </div>
            <div className="flex-1">
              <div className="text-chimera-low">removed</div>
              <ul className="list-disc pl-5">
                {result.sdks_removed.map((s) => <li key={s}><code>{s}</code></li>)}
              </ul>
            </div>
          </div>
        </section>
      )}
    </div>
  )
}
