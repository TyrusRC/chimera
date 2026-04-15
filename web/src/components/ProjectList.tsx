import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { useStore } from '../store'

export function ProjectList() {
  const [projects, setProjects] = useState<any[]>([])
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [info, setInfo] = useState<any>(null)
  const setProject = useStore((s) => s.setProject)

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
    api.getInfo().then(setInfo).catch(() => {})
  }, [])

  const handleAnalyze = async () => {
    if (!path) return
    setLoading(true)
    try {
      const result = await api.createProject(path)
      setProject(result.id)
    } catch (e: any) {
      alert(e.message)
    }
    setLoading(false)
  }

  return (
    <div className="flex items-center justify-center h-screen bg-chimera-bg">
      <div className="w-[500px] bg-chimera-surface rounded-lg border border-chimera-border p-6">
        <h1 className="text-xl font-bold text-chimera-accent mb-1">Chimera</h1>
        <p className="text-chimera-muted text-xs mb-6">
          {info ? `v${info.version} — Mobile RE Platform` : 'Loading...'}
        </p>

        <div className="mb-6">
          <label className="block text-xs text-chimera-muted mb-1">Analyze a binary</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/path/to/app.apk or app.ipa"
              className="flex-1 bg-chimera-bg border border-chimera-border rounded px-3 py-2 text-sm text-chimera-text placeholder-chimera-muted focus:outline-none focus:border-chimera-accent"
            />
            <button
              onClick={handleAnalyze}
              disabled={loading || !path}
              className="bg-chimera-accent text-chimera-bg px-4 py-2 rounded text-sm font-medium hover:opacity-90 disabled:opacity-50"
            >
              {loading ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>
        </div>

        {projects.length > 0 && (
          <div>
            <h2 className="text-xs text-chimera-muted mb-2">Recent projects</h2>
            {projects.map((p) => (
              <button
                key={p.id}
                onClick={() => setProject(p.id)}
                className="w-full text-left px-3 py-2 text-xs rounded hover:bg-chimera-panel mb-1 border border-chimera-border/50"
              >
                <span className="text-chimera-text">{p.name}</span>
                <span className="text-chimera-muted ml-2">({p.platform})</span>
                <span className="text-chimera-muted ml-2">{p.finding_count} findings</span>
                <span className={`ml-2 ${p.status === 'complete' ? 'text-chimera-low' : 'text-chimera-medium'}`}>
                  {p.status}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
