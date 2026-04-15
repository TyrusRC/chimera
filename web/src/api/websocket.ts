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
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!projectId) return

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const url = `${protocol}//${window.location.host}/ws/analysis/${projectId}`
      const socket = new WebSocket(url)

      socket.onmessage = (event) => {
        try {
          const data: AnalysisProgress = JSON.parse(event.data)
          if (data.project_id && data.phase !== undefined) {
            setProgress(data)
          }
        } catch {
          // Ignore malformed messages
        }
      }

      socket.onclose = () => {
        setProgress(null)
        // Reconnect after 3s if component still mounted
        reconnectTimer.current = setTimeout(connect, 3000)
      }

      socket.onerror = () => {
        socket.close()
      }

      ws.current = socket
    }

    connect()

    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [projectId])

  return progress
}
