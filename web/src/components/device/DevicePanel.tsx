import { useEffect, useState } from 'react'

export function DevicePanel() {
  const [devices, setDevices] = useState<any[]>([])

  useEffect(() => {
    fetch('/api/devices').then(r => r.json()).then(setDevices).catch(() => {})
  }, [])

  return (
    <div className="p-4">
      <h3 className="text-sm font-bold text-chimera-text mb-3">Connected Devices</h3>
      {devices.length === 0 ? (
        <div className="text-chimera-muted text-xs">No devices connected. Connect via USB and ensure ADB/libimobiledevice is available.</div>
      ) : (
        <div className="space-y-2">
          {devices.map((d: any) => (
            <div key={d.id} className="bg-chimera-surface border border-chimera-border rounded p-3 text-xs">
              <div className="flex justify-between">
                <span className="text-chimera-accent font-bold">{d.platform}</span>
                <span className={d.is_rooted || d.is_jailbroken ? 'text-chimera-low' : 'text-chimera-muted'}>
                  {d.is_rooted ? 'rooted' : d.is_jailbroken ? 'jailbroken' : 'stock'}
                </span>
              </div>
              <div className="text-chimera-text mt-1">{d.model || '?'} — {d.os_version || '?'}</div>
              <div className="text-chimera-muted mt-1 font-mono">{d.id}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
