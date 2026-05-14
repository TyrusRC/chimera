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

interface Transform {
  pan: { x: number; y: number }
  zoom: number
}

export function CallGraph({ projectId, address }: Props) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [data, setData] = useState<CallGraphData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 0, h: 0 })
  const [transform, setTransform] = useState<Transform>({ pan: { x: 0, y: 0 }, zoom: 1 })
  const transformRef = useRef<Transform>(transform)
  transformRef.current = transform
  const selectFunction = useStore((s) => s.selectFunction)

  useEffect(() => {
    if (!address) return
    setError(null)
    api.getCallGraph(projectId, address)
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [projectId, address])

  // Reset transform when the underlying graph changes
  useEffect(() => {
    setTransform({ pan: { x: 0, y: 0 }, zoom: 1 })
  }, [data])

  // Observe container size for resize + initial layout
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const cr = entry.contentRect
        setSize({ w: Math.floor(cr.width), h: Math.floor(cr.height) })
      }
    })
    ro.observe(el)
    // Initial seed in case ResizeObserver doesn't fire immediately
    setSize({ w: Math.floor(el.clientWidth), h: Math.floor(el.clientHeight) })
    return () => ro.disconnect()
  }, [data])

  // Layout + draw
  useEffect(() => {
    if (!data || !canvasRef.current) return
    if (size.w <= 0 || size.h <= 0) return
    const canvas = canvasRef.current
    const dpr = window.devicePixelRatio || 1
    canvas.width = size.w * dpr
    canvas.height = size.h * dpr
    canvas.style.width = `${size.w}px`
    canvas.style.height = `${size.h}px`
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.setTransform(1, 0, 0, 1, 0, 0)
    ctx.scale(dpr, dpr)

    const cx = size.w / 2
    const cy = size.h / 2
    const radius = Math.min(cx, cy) * 0.65

    // Radial layout
    const nodes = data.nodes.map((n, i) => ({
      ...n,
      x: cx + Math.cos((i * 2 * Math.PI) / data.nodes.length) * radius,
      y: cy + Math.sin((i * 2 * Math.PI) / data.nodes.length) * radius,
    }))
    const nodeMap = Object.fromEntries(nodes.map((n) => [n.id, n]))

    ctx.clearRect(0, 0, size.w, size.h)

    // Apply pan/zoom for world drawing
    ctx.save()
    ctx.translate(transform.pan.x, transform.pan.y)
    ctx.scale(transform.zoom, transform.zoom)

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

    ctx.restore()

    const handler = (e: MouseEvent) => {
      // Suppress click that immediately follows a drag (see pointer logic)
      if (didDragRef.current) {
        didDragRef.current = false
        return
      }
      const rect = canvas.getBoundingClientRect()
      const mx = e.clientX - rect.left
      const my = e.clientY - rect.top
      const t = transformRef.current
      const wx = (mx - t.pan.x) / t.zoom
      const wy = (my - t.pan.y) / t.zoom
      for (const n of nodes) {
        if (Math.hypot(n.x - wx, n.y - wy) < 12) {
          selectFunction(n.id)
          break
        }
      }
    }
    canvas.addEventListener('click', handler)
    return () => canvas.removeEventListener('click', handler)
  }, [data, selectFunction, size, transform])

  // Wheel + pointer drag (attach once per canvas mount, use refs to read latest transform)
  const didDragRef = useRef(false)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const t = transformRef.current
      if (e.ctrlKey || e.metaKey) {
        // Zoom around the cursor position
        const rect = canvas.getBoundingClientRect()
        const mx = e.clientX - rect.left
        const my = e.clientY - rect.top
        const factor = Math.exp(-e.deltaY * 0.0015)
        const nextZoom = Math.min(5, Math.max(0.1, t.zoom * factor))
        // Keep the world point under the cursor stationary
        const wx = (mx - t.pan.x) / t.zoom
        const wy = (my - t.pan.y) / t.zoom
        const nextPan = { x: mx - wx * nextZoom, y: my - wy * nextZoom }
        setTransform({ pan: nextPan, zoom: nextZoom })
      } else {
        setTransform({
          pan: { x: t.pan.x - e.deltaX, y: t.pan.y - e.deltaY },
          zoom: t.zoom,
        })
      }
    }

    let dragging = false
    let lastX = 0
    let lastY = 0
    let downX = 0
    let downY = 0

    const onPointerDown = (e: PointerEvent) => {
      if (e.button !== 0) return
      dragging = true
      didDragRef.current = false
      lastX = e.clientX
      lastY = e.clientY
      downX = e.clientX
      downY = e.clientY
      canvas.setPointerCapture(e.pointerId)
    }

    const onPointerMove = (e: PointerEvent) => {
      if (!dragging) return
      const dx = e.clientX - lastX
      const dy = e.clientY - lastY
      lastX = e.clientX
      lastY = e.clientY
      if (Math.hypot(e.clientX - downX, e.clientY - downY) > 3) {
        didDragRef.current = true
      }
      const t = transformRef.current
      setTransform({ pan: { x: t.pan.x + dx, y: t.pan.y + dy }, zoom: t.zoom })
    }

    const endDrag = (e: PointerEvent) => {
      if (!dragging) return
      dragging = false
      try {
        canvas.releasePointerCapture(e.pointerId)
      } catch {
        /* ignore */
      }
    }

    canvas.addEventListener('wheel', onWheel, { passive: false })
    canvas.addEventListener('pointerdown', onPointerDown)
    canvas.addEventListener('pointermove', onPointerMove)
    canvas.addEventListener('pointerup', endDrag)
    canvas.addEventListener('pointercancel', endDrag)
    return () => {
      canvas.removeEventListener('wheel', onWheel)
      canvas.removeEventListener('pointerdown', onPointerDown)
      canvas.removeEventListener('pointermove', onPointerMove)
      canvas.removeEventListener('pointerup', endDrag)
      canvas.removeEventListener('pointercancel', endDrag)
    }
  }, [data])

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

  return (
    <div ref={containerRef} className="w-full h-full bg-chimera-bg">
      <canvas
        ref={canvasRef}
        className="block bg-chimera-bg"
        style={{ cursor: 'grab', touchAction: 'none' }}
      />
    </div>
  )
}
