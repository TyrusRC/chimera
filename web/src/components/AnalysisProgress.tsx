import { useAnalysisProgress } from '../api/websocket'

interface Props { projectId: string }

export function AnalysisProgress({ projectId }: Props) {
  const progress = useAnalysisProgress(projectId)

  if (!progress) return null

  return (
    <div className="px-3 py-2 bg-chimera-surface border-b border-chimera-border">
      <div className="flex items-center gap-3 text-xs">
        <div className="animate-spin w-3 h-3 border-2 border-chimera-accent border-t-transparent rounded-full" />
        <span className="text-chimera-accent">{progress.phase}</span>
        <span className="text-chimera-muted">{progress.detail}</span>
        <div className="flex-1 bg-chimera-bg rounded-full h-1.5">
          <div
            className="bg-chimera-accent h-1.5 rounded-full transition-all"
            style={{ width: `${progress.percent}%` }}
          />
        </div>
        <span className="text-chimera-muted">{progress.percent}%</span>
      </div>
    </div>
  )
}
