import { useEffect, useState } from 'react'
import Editor from '@monaco-editor/react'
import { api } from '../api/client'

interface Props { projectId: string; address: string | null }

export function CodeView({ projectId, address }: Props) {
  const [code, setCode] = useState('')
  const [funcName, setFuncName] = useState('')
  const [language, setLanguage] = useState('c')

  useEffect(() => {
    if (!address) {
      setCode('// Select a function from the sidebar to view decompiled code')
      setFuncName('')
      return
    }
    const ac = new AbortController()
    api.getFunction(projectId, address, ac.signal).then((f) => {
      if (ac.signal.aborted) return
      setFuncName(`${f.name} (${f.address})`)
      setCode(f.decompiled || `// No decompiled code available for ${f.name}\n// Backend: ${f.source_backend}`)
      const langMap: Record<string, string> = { java: 'java', kotlin: 'kotlin', c: 'c', objc: 'objective-c', swift: 'swift' }
      setLanguage(langMap[f.language] || 'c')
    }).catch(() => { if (!ac.signal.aborted) setCode('// Error loading function') })
    return () => ac.abort()
  }, [projectId, address])

  return (
    <div className="h-full flex flex-col">
      {funcName && (
        <div className="px-3 py-1 bg-chimera-surface border-b border-chimera-border text-xs text-chimera-accent font-mono">
          {funcName}
        </div>
      )}
      <div className="flex-1">
        <Editor
          theme="vs-dark"
          language={language}
          value={code}
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
