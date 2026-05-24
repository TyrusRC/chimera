import { useEffect, useRef, useState } from 'react'
import Editor, { OnMount } from '@monaco-editor/react'
import type { editor as MonacoEditor } from 'monaco-editor'
import { api } from '../api/client'

interface Props { projectId: string; address: string | null }

type DecompBackend = 'r2' | 'ghidra'

export function CodeView({ projectId, address }: Props) {
  const [code, setCode] = useState('')
  const [funcName, setFuncName] = useState('')
  const [language, setLanguage] = useState('c')
  const [backend, setBackend] = useState<DecompBackend>('r2')
  const [decompMeta, setDecompMeta] = useState<{ lines: number; error?: string } | null>(null)
  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null)
  // Stash mutables on a ref so Monaco actions registered once still see fresh state.
  const ctx = useRef({ projectId, address })
  ctx.current = { projectId, address }

  // Load function decomp + metadata. Pulls post-processed C from /decomp,
  // falls back to FunctionInfo.decompiled if the endpoint says no.
  useEffect(() => {
    if (!address) {
      setCode('// Select a function from the sidebar to view decompiled code')
      setFuncName('')
      setDecompMeta(null)
      return
    }
    const ac = new AbortController()
    Promise.all([
      api.getFunction(projectId, address, ac.signal),
      api.getDecomp(projectId, address, backend, ac.signal).catch(() => null),
    ]).then(([f, decomp]) => {
      if (ac.signal.aborted) return
      setFuncName(`${f.name} (${f.address})`)
      const langMap: Record<string, string> = {
        java: 'java', kotlin: 'kotlin', c: 'c', objc: 'objective-c', swift: 'swift',
      }
      setLanguage(langMap[f.language] || 'c')
      const b = decomp?.backends?.[backend]
      if (b?.ok && b.code) {
        setCode(b.code)
        setDecompMeta({ lines: b.lines })
      } else if (f.decompiled) {
        setCode(f.decompiled)
        setDecompMeta(null)
      } else {
        setCode(`// No decompiled code available for ${f.name}\n// Backend: ${f.source_backend}\n` +
                (b?.error ? `// ${backend} error: ${b.error}\n` : ''))
        setDecompMeta(b?.error ? { lines: 0, error: b.error } : null)
      }
    }).catch(() => {
      if (!ac.signal.aborted) setCode('// Error loading function')
    })
    return () => ac.abort()
  }, [projectId, address, backend])

  const handleMount: OnMount = (editor, monaco) => {
    editorRef.current = editor

    // Right-click → "Rename function…". F2 also works (Monaco default keybinding).
    editor.addAction({
      id: 'chimera.renameFunction',
      label: 'Rename function…',
      keybindings: [monaco.KeyCode.F2],
      contextMenuGroupId: 'navigation',
      contextMenuOrder: 1,
      run: async () => {
        const { projectId, address } = ctx.current
        if (!address) return
        const current = funcName.replace(/\s*\(.*$/, '')
        const next = window.prompt(`Rename function (was: ${current})`, current)
        if (!next || next === current) return
        try {
          await api.renameAnnotation(projectId, {
            kind: 'function', address, new_name: next,
          })
          // Re-fetch so the name + any cross-refs surface immediately.
          const f = await api.getFunction(projectId, address)
          setFuncName(`${f.name} (${f.address})`)
        } catch (e) {
          window.alert(`Rename failed: ${(e as Error).message}`)
        }
      },
    })

    // Right-click → "Add comment on this line".
    editor.addAction({
      id: 'chimera.addComment',
      label: 'Add comment on this line',
      contextMenuGroupId: 'navigation',
      contextMenuOrder: 2,
      run: async (ed) => {
        const { projectId, address } = ctx.current
        if (!address) return
        const line = ed.getPosition()?.lineNumber ?? 0
        const text = window.prompt(`Comment at line ${line}`)
        if (!text) return
        try {
          await api.commentAnnotation(projectId, { address, text, line })
        } catch (e) {
          window.alert(`Comment failed: ${(e as Error).message}`)
        }
      },
    })

    // Right-click → "Set function signature/type…".
    editor.addAction({
      id: 'chimera.setType',
      label: 'Set function signature…',
      contextMenuGroupId: 'navigation',
      contextMenuOrder: 3,
      run: async () => {
        const { projectId, address } = ctx.current
        if (!address) return
        const sig = window.prompt('Function signature (e.g. int decode(char* in, int len))')
        if (!sig) return
        try {
          await api.typeAnnotation(projectId, { address, signature: sig })
        } catch (e) {
          window.alert(`Set type failed: ${(e as Error).message}`)
        }
      },
    })
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-1 bg-chimera-surface border-b border-chimera-border flex items-center gap-3 text-xs">
        {funcName && (
          <span className="text-chimera-accent font-mono">{funcName}</span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <label className="text-chimera-muted">Decompiler:</label>
          <select
            value={backend}
            onChange={(e) => setBackend(e.target.value as DecompBackend)}
            className="bg-chimera-panel border border-chimera-border text-chimera-text px-2 py-0.5 rounded"
          >
            <option value="r2">radare2</option>
            <option value="ghidra">Ghidra</option>
          </select>
          {decompMeta && (
            <span className="text-chimera-muted">{decompMeta.lines} lines</span>
          )}
        </div>
      </div>
      <div className="flex-1">
        <Editor
          theme="vs-dark"
          language={language}
          value={code}
          onMount={handleMount}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            fontSize: 13,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            lineNumbers: 'on',
            scrollBeyondLastLine: false,
            wordWrap: 'on',
          }}
        />
      </div>
    </div>
  )
}
