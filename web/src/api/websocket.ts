import { useEffect, useRef, useState } from 'react'

interface AnalysisProgress {
  project_id: string
  phase: string
  detail: string
  percent: number
}

export function useAnalysisProgress(projectId: string | null) {
  const [progress, setProgress] = useState<AnalysisProgress | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const cancelledRef = useRef(false)

  useEffect(() => {
    if (!projectId) return
    cancelledRef.current = false

    function clearReconnectTimer() {
      if (timerRef.current) {
        clearTimeout(timerRef.current)
        timerRef.current = null
      }
    }

    function connect() {
      if (cancelledRef.current) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const url = `${protocol}//${window.location.host}/ws/analysis/${projectId}`
      const socket = new WebSocket(url)

      socket.onmessage = (event) => {
        if (cancelledRef.current) return
        try {
          const data: AnalysisProgress = JSON.parse(event.data)
          if (data.project_id && data.phase !== undefined) {
            setProgress(data)
          }
        } catch {
          // ignore
        }
      }

      socket.onclose = () => {
        if (cancelledRef.current) return
        setProgress(null)
        clearReconnectTimer()
        timerRef.current = setTimeout(connect, 3000)
      }

      socket.onerror = () => {
        // onerror is always followed by onclose; let onclose schedule the reconnect.
        try { socket.close() } catch { /* already closing */ }
      }

      wsRef.current = socket
    }

    connect()

    return () => {
      cancelledRef.current = true
      clearReconnectTimer()
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [projectId])

  return progress
}
