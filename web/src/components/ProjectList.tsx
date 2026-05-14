import { useEffect, useRef, useState } from 'react'
import { api, ProjectSummary } from '../api/client'
import { useStore } from '../store'

const ACCEPTED_FILE_TYPES =
  '.apk,.aab,.ipa,.xapk,.apkm,.exe,.dll,.so,.dylib,.elf,.macho,.dex,.jar'

export function ProjectList() {
  const [projects, setProjects] = useState<ProjectSummary[]>([])
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [info, setInfo] = useState<{ name: string; version: string } | null>(null)
  const setProject = useStore((s) => s.setProject)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    api.listProjects().then(setProjects).catch(() => {})
    api.getInfo().then(setInfo).catch(() => {})
  }, [])

  const analyzePath = async (target: string) => {
    setLoading(true)
    try {
      const result = await api.createProject(target)
      setProject(result.id)
    } catch (e: any) {
      alert(e.message)
    }
    setLoading(false)
  }

  const handleAnalyze = async () => {
    if (!path) return
    await analyzePath(path)
  }

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      const { path: uploadedPath } = await api.uploadProject(file)
      setPath(uploadedPath)
      await analyzePath(uploadedPath)
    } catch (err: any) {
      alert(err.message)
    } finally {
      setUploading(false)
      // Reset the input so selecting the same file again re-triggers the handler
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
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
              disabled={loading || uploading || !path}
              className="bg-chimera-accent text-chimera-bg px-4 py-2 rounded text-sm font-medium hover:opacity-90 disabled:opacity-50"
            >
              {loading ? 'Analyzing...' : 'Analyze'}
            </button>
          </div>
          <div className="mt-2 flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept={ACCEPTED_FILE_TYPES}
              onChange={handleFileChange}
              disabled={uploading || loading}
              className="hidden"
              id="chimera-upload-input"
            />
            <label
              htmlFor="chimera-upload-input"
              className={`text-xs px-3 py-1.5 rounded border border-chimera-border text-chimera-muted hover:text-chimera-text hover:border-chimera-accent cursor-pointer ${
                uploading || loading ? 'opacity-50 pointer-events-none' : ''
              }`}
            >
              {uploading ? 'Uploading...' : 'Upload binary...'}
            </label>
            <span className="text-[10px] text-chimera-muted">
              .apk .aab .ipa .xapk .exe .dll .so .dylib .elf .dex .jar
            </span>
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
