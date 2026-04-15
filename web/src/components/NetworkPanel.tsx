interface Props { projectId: string }
export function NetworkPanel({ projectId }: Props) {
  return (
    <div className="p-4 text-chimera-muted text-xs">
      <h3 className="text-sm font-bold text-chimera-text mb-2">Network Capture</h3>
      <p>Connect a device and start mitmproxy to capture traffic.</p>
      <p className="mt-2">Use: <code className="text-chimera-accent">chimera serve</code> + configure device proxy to this host:8080</p>
      <div className="mt-4 border border-chimera-border rounded p-3">
        <div className="text-chimera-muted">No traffic captured yet</div>
      </div>
    </div>
  )
}
