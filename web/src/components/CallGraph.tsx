import { useEffect, useRef, useState } from 'react'
import { api, CallGraphData } from '../api/client'
import { useStore } from '../store'

interface Props {
  projectId: string
  address: string | null
}

const classColors: Record<string, string> = {
  crypto: '#f38ba8',
  utility: '#89b4fa',
  handler: '#a6e3a1',
  init: '#f9e2af',
  parser: '#fab387',
  unknown: '#6c7086',
}

export function CallGraph({ projectId, address }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [data, setData] = useState<CallGraphData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const selectFunction = useStore((s) => s.selectFunction)

  useEffect(() => {
    if (!address) return
    setError(null)
    api.getCallGraph(projectId, address)
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [projectId, address])

  useEffect(() => {
    if (!data || !canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    canvas.width = canvas.offsetWidth
    canvas.height = canvas.offsetHeight

    const cx = canvas.width / 2
    const cy = canvas.height / 2
    const radius = Math.min(cx, cy) * 0.65

    // Radial layout
    const nodes = data.nodes.map((n, i) => ({
      ...n,
      x: cx + Math.cos((i * 2 * Math.PI) / data.nodes.length) * radius,
      y: cy + Math.sin((i * 2 * Math.PI) / data.nodes.length) * radius,
    }))
    const nodeMap = Object.fromEntries(nodes.map((n) => [n.id, n]))

    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Draw edges
    data.edges.forEach((e) => {
      const src = nodeMap[e.source]
      const tgt = nodeMap[e.target]
      if (!src || !tgt) return
      ctx.beginPath()
      ctx.strokeStyle = '#3a3a5a'
      ctx.lineWidth = 1
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)
      ctx.stroke()

      // Arrow head
      const dx = tgt.x - src.x
      const dy = tgt.y - src.y
      const angle = Math.atan2(dy, dx)
      const ax = tgt.x - Math.cos(angle) * 12
      const ay = tgt.y - Math.sin(angle) * 12
      ctx.beginPath()
      ctx.fillStyle = '#3a3a5a'
      ctx.moveTo(tgt.x - Math.cos(angle) * 8, tgt.y - Math.sin(angle) * 8)
      ctx.lineTo(ax - Math.cos(angle - 0.5) * 5, ay - Math.sin(angle - 0.5) * 5)
      ctx.lineTo(ax - Math.cos(angle + 0.5) * 5, ay - Math.sin(angle + 0.5) * 5)
      ctx.fill()
    })

    // Draw nodes
    nodes.forEach((n) => {
      ctx.beginPath()
      ctx.fillStyle = classColors[n.classification] ?? classColors.unknown
      ctx.arc(n.x, n.y, 8, 0, Math.PI * 2)
      ctx.fill()
      ctx.fillStyle = '#cdd6f4'
      ctx.font = '10px monospace'
      ctx.fillText(n.name.length > 24 ? n.name.slice(0, 22) + '…' : n.name, n.x + 12, n.y + 4)
    })

    const handler = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      for (const n of nodes) {
        if (Math.hypot(n.x - mx, n.y - my) < 12) {
          selectFunction(n.id)
          break
        }
      }
    }
    canvas.addEventListener('click', handler)
    return () => canvas.removeEventListener('click', handler)
  }, [data, selectFunction])

  if (!address) {
    return (
      <div className="p-4 text-chimera-muted text-xs">
        Select a function to view call graph
      </div>
    )
  }

  if (error) {
    return <div className="p-4 text-chimera-muted text-xs">Failed to load call graph: {error}</div>
  }

  return <canvas ref={canvasRef} className="w-full h-full bg-chimera-bg" />
}
