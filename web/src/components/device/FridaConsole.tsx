import { useState } from 'react'

export function FridaConsole() {
  const [input, setInput] = useState('')
  const [output, setOutput] = useState<string[]>(['// Frida console — connect to a device first'])

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto bg-chimera-bg p-2 font-mono text-xs">
        {output.map((line, i) => (
          <div key={i} className="text-chimera-text">{line}</div>
        ))}
      </div>
      <div className="border-t border-chimera-border p-2 flex gap-2">
        <span className="text-chimera-accent text-xs font-mono">frida&gt;</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && input) {
              setOutput([...output, `> ${input}`, '// (Frida not connected)'])
              setInput('')
            }
          }}
          className="flex-1 bg-transparent text-chimera-text text-xs font-mono focus:outline-none"
          placeholder="Type JavaScript..."
        />
      </div>
    </div>
  )
}
