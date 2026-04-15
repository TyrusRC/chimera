import { useEffect, useState } from 'react'
import { api } from '../../api/client'

interface Props { projectId: string }

export function StatusBar({ projectId }: Props) {
  const [project, setProject] = useState<any>(null)

  useEffect(() => {
    api.getProject(projectId).then(setProject).catch(() => {})
  }, [projectId])

  return (
    <div className="h-6 bg-chimera-surface border-t border-chimera-border flex items-center px-3 text-[10px] text-chimera-muted gap-4">
      <span>Project: {project?.name || '...'}</span>
      <span>Platform: {project?.platform || '...'}</span>
      <span>Functions: {project?.function_count ?? '...'}</span>
      <span>Strings: {project?.string_count ?? '...'}</span>
      <span>Findings: {project?.finding_count ?? '...'}</span>
      <span className="ml-auto">Chimera v0.1.0</span>
    </div>
  )
}
