import { useEffect, useRef, useState } from 'react'

interface AnalysisProgress {
  project_id: string
  phase: string
  detail: string
  percent: number
}

export function useAnalysisProgress(projectId: string | null) {
  const [progress, setProgress] = useState<AnalysisProgress | null>(null)
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!projectId) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws/analysis/${projectId}`
    const socket = new WebSocket(url)

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        setProgress(data)
      } catch {}
    }

    socket.onclose = () => setProgress(null)
    ws.current = socket

    return () => { socket.close() }
  }, [projectId])

  return progress
}
