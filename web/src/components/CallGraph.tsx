import { useEffect, useRef, useState } from 'react'
import { useStore } from '../store'

interface Props {
  projectId: string
  address: string | null
}

interface Node {
  id: string
  name: string
  classification: string
  layer: string
  x?: number
  y?: number
}

interface Edge {
  source: string
  target: string
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
  const [data, setData] = useState<{ nodes: Node[]; edges: Edge[] } | null>(null)
  const selectFunction = useStore((s) => s.selectFunction)

  useEffect(() => {
    if (!address) return
    fetch(`/api/projects/${projectId}/callgraph/${address}?depth=2`)
      .then((r) => r.json())
      .then(setData)
      .catch(() => {})
  }, [projectId, address])

  useEffect(() => {
    if (!data || !canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    canvas.width = canvas.offsetWidth
    canvas.height = canvas.offsetHeight

    // Simple radial layout — one tick of force simulation would improve clustering
    const nodes = data.nodes.map((n, i) => ({
      ...n,
      x: canvas.width / 2 + Math.cos(i * 2.4) * 120,
      y: canvas.height / 2 + Math.sin(i * 2.4) * 120,
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
      ctx.moveTo(src.x!, src.y!)
      ctx.lineTo(tgt.x!, tgt.y!)
      ctx.stroke()
    })

    // Draw nodes
    nodes.forEach((n) => {
      ctx.beginPath()
      ctx.fillStyle = classColors[n.classification] ?? classColors.unknown
      ctx.arc(n.x!, n.y!, 8, 0, Math.PI * 2)
      ctx.fill()
      ctx.fillStyle = '#cdd6f4'
      ctx.font = '10px monospace'
      ctx.fillText(n.name.slice(0, 20), n.x! + 12, n.y! + 4)
    })

    canvas.onclick = (e) => {
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      for (const n of nodes) {
        if (Math.hypot(n.x! - mx, n.y! - my) < 12) {
          selectFunction(n.id)
          break
        }
      }
    }
  }, [data])

  if (!address) {
    return (
      <div className="p-4 text-chimera-muted text-xs">
        Select a function to view call graph
      </div>
    )
  }

  return <canvas ref={canvasRef} className="w-full h-full bg-chimera-bg" />
}
