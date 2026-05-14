import { useEffect, useRef, useState } from 'react'
import { api, FridaScriptMeta } from '../../api/client'

interface Props {
  deviceId: string | null
  platform: string | null  // "android" | "ios" | null
}

interface LogLine {
  kind: 'in' | 'out' | 'send' | 'error' | 'sys'
  text: string
}

const MAX_LINES = 10_000

export function FridaConsole({ deviceId, platform }: Props) {
  const [packages, setPackages] = useState<string[]>([])
  const [scripts, setScripts] = useState<FridaScriptMeta[]>([])
  const [target, setTarget] = useState<string>('')
  const [mode, setMode] = useState<'attach' | 'spawn'>('attach')
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [lines, setLines] = useState<LogLine[]>([{ kind: 'sys', text: '// Frida console — pick a device and target' }])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const ws = useRef<WebSocket | null>(null)
  const sessionIdRef = useRef<string | null>(null)
  useEffect(() => { sessionIdRef.current = sessionId }, [sessionId])
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // Auto-scroll on new lines (gated by toggle)
  useEffect(() => {
    if (!autoScroll) return
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
  }, [lines, autoScroll])

  // On unmount: close WS and tell backend to release the Frida session.
  useEffect(() => {
    return () => {
      ws.current?.close()
      ws.current = null
      const sid = sessionIdRef.current
      if (sid) {
        // Fire-and-forget — the component is going away; no UI update on result.
        api.closeFridaSession(sid).catch(() => {})
      }
    }
  }, [])

  // Load bundled scripts once
  useEffect(() => {
    const ac = new AbortController()
    api.listFridaScripts(ac.signal)
      .then((r) => {
        if (ac.signal.aborted) return
        setScripts(r.scripts.filter((s) => !platform || s.platform === platform || s.platform === 'both'))
      })
      .catch((e: Error) => { if (!ac.signal.aborted) setError(`scripts: ${e.message}`) })
    return () => ac.abort()
  }, [platform])

  // Refresh package list whenever the device changes
  useEffect(() => {
    if (!deviceId) {
      setPackages([])
      return
    }
    const ac = new AbortController()
    api.listPackages(deviceId, ac.signal)
      .then((r) => { if (!ac.signal.aborted) setPackages(r.packages) })
      .catch((e: Error) => { if (!ac.signal.aborted) setError(`packages: ${e.message}`) })
    return () => ac.abort()
  }, [deviceId])

  function log(line: LogLine) {
    setLines((prev) => {
      if (prev.length < MAX_LINES) return [...prev, line]
      // Drop oldest to keep the buffer bounded.
      return [...prev.slice(prev.length - MAX_LINES + 1), line]
    })
  }

  function clearBuffer() {
    setLines([{ kind: 'sys', text: '// buffer cleared' }])
  }

  function saveSession() {
    const sid = sessionIdRef.current || 'unknown'
    const text = lines.map((l) => JSON.stringify(l)).join('\n')
    const blob = new Blob([text], { type: 'application/x-ndjson' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `frida-session-${sid}-${Date.now()}.jsonl`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function connect() {
    if (!target) {
      setError('pick a target package')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const r = await api.createFridaSession({
        device_id: deviceId || undefined,
        target,
        mode,
      })
      setSessionId(r.session_id)
      log({ kind: 'sys', text: `// connected (mode=${mode} target=${target} sid=${r.session_id})` })
      openWs(r.session_id)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  function openWs(sid: string) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws/frida/${sid}`
    const socket = new WebSocket(url)
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'send') {
          log({ kind: 'send', text: typeof data.payload === 'string' ? data.payload : JSON.stringify(data.payload) })
        } else if (data.type === 'error') {
          log({ kind: 'error', text: data.description || data.message || JSON.stringify(data) })
        } else {
          log({ kind: 'sys', text: JSON.stringify(data) })
        }
      } catch {
        // ignore non-json frames (e.g. pong)
      }
    }
    socket.onclose = () => {
      log({ kind: 'sys', text: '// ws closed' })
      setSessionId(null)
      ws.current = null
    }
    socket.onerror = () => log({ kind: 'error', text: '// ws error' })
    ws.current = socket
  }

  async function disconnect() {
    if (!sessionId) return
    setBusy(true)
    try {
      await api.closeFridaSession(sessionId)
    } catch (e) {
      log({ kind: 'error', text: (e as Error).message })
    }
    ws.current?.close()
    ws.current = null
    setSessionId(null)
    setBusy(false)
    log({ kind: 'sys', text: '// disconnected' })
  }

  async function submit() {
    if (!sessionId || !input) return
    const code = input
    setInput('')
    log({ kind: 'in', text: `> ${code}` })
    try {
      const r = await api.execFrida(sessionId, code)
      log({ kind: 'out', text: r.result })
    } catch (e) {
      log({ kind: 'error', text: (e as Error).message })
    }
  }

  async function loadScript(scriptId: string) {
    if (!sessionId) return
    log({ kind: 'sys', text: `// loading ${scriptId}` })
    try {
      await api.loadFridaScript(sessionId, { script_id: scriptId })
      log({ kind: 'sys', text: `// loaded ${scriptId}` })
    } catch (e) {
      log({ kind: 'error', text: (e as Error).message })
    }
  }

  const colorFor = (kind: LogLine['kind']) => {
    switch (kind) {
      case 'in': return 'text-chimera-accent'
      case 'out': return 'text-chimera-text'
      case 'send': return 'text-chimera-low'
      case 'error': return 'text-chimera-critical'
      case 'sys': return 'text-chimera-muted'
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="border-b border-chimera-border p-2 flex flex-wrap items-center gap-2 text-xs">
        {!sessionId ? (
          <>
            {packages.length > 0 ? (
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="bg-chimera-surface text-chimera-text border border-chimera-border rounded px-2 py-1 font-mono"
              >
                <option value="">-- pick package --</option>
                {packages.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            ) : (
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="com.example.app"
                className="bg-chimera-surface text-chimera-text border border-chimera-border rounded px-2 py-1 font-mono"
              />
            )}
            <label className="text-chimera-muted">
              <input type="radio" checked={mode === 'attach'} onChange={() => setMode('attach')} /> attach
            </label>
            <label className="text-chimera-muted">
              <input type="radio" checked={mode === 'spawn'} onChange={() => setMode('spawn')} /> spawn
            </label>
            <button
              onClick={connect}
              disabled={busy || !target}
              className="bg-chimera-accent text-chimera-bg px-3 py-1 rounded disabled:opacity-50"
            >
              Connect
            </button>
          </>
        ) : (
          <>
            <span className="text-chimera-muted font-mono">{target} ({mode})</span>
            <select
              onChange={(e) => { if (e.target.value) { loadScript(e.target.value); e.currentTarget.value = '' } }}
              className="bg-chimera-surface text-chimera-text border border-chimera-border rounded px-2 py-1"
            >
              <option value="">-- load script --</option>
              {scripts.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <button
              onClick={disconnect}
              disabled={busy}
              className="bg-chimera-surface border border-chimera-border text-chimera-text px-3 py-1 rounded"
            >
              Disconnect
            </button>
          </>
        )}
        {error && <span className="text-chimera-critical">{error}</span>}
        <div className="ml-auto flex items-center gap-2 text-[10px] text-chimera-muted">
          <label className="flex items-center gap-1 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            auto-scroll
          </label>
          <span>{lines.length}/{MAX_LINES}</span>
          <button
            onClick={saveSession}
            className="px-2 py-0.5 border border-chimera-border rounded hover:text-chimera-text"
            title="Download buffer as .jsonl"
          >
            Save
          </button>
          <button
            onClick={clearBuffer}
            className="px-2 py-0.5 border border-chimera-border rounded hover:text-chimera-text"
          >
            Clear
          </button>
        </div>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto bg-chimera-bg p-2 font-mono text-xs">
        {lines.map((l, i) => (
          <div key={i} className={colorFor(l.kind)}>{l.text}</div>
        ))}
      </div>

      <div className="border-t border-chimera-border p-2 flex gap-2">
        <span className="text-chimera-accent text-xs font-mono">frida&gt;</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') submit() }}
          disabled={!sessionId}
          className="flex-1 bg-transparent text-chimera-text text-xs font-mono focus:outline-none disabled:opacity-40"
          placeholder={sessionId ? 'Type JavaScript...' : 'Connect to a session first'}
        />
      </div>
    </div>
  )
}
