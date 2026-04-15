import { useEffect, useState } from 'react'
import { api } from '../api/client'

interface Props {
  projectId: string
}

interface Finding {
  rule_id: string
  title: string
  severity: string
  masvs_category?: string
  location?: string
  description?: string
}

interface ProtectionItem {
  id: string
  label: string
  description: string
  detected: boolean
  severity: string
  relatedRules: string[]
}

const PROTECTION_CHECKS: Omit<ProtectionItem, 'detected'>[] = [
  {
    id: 'root_detection',
    label: 'Root / Jailbreak Detection',
    description: 'App checks for root access or jailbreak conditions.',
    severity: 'high',
    relatedRules: ['M8', 'ROOT'],
  },
  {
    id: 'ssl_pinning',
    label: 'SSL/TLS Certificate Pinning',
    description: 'App validates server certificate against a hard-coded pin.',
    severity: 'high',
    relatedRules: ['M3', 'PINNING', 'SSL'],
  },
  {
    id: 'anti_debug',
    label: 'Anti-Debugging',
    description: 'App detects or blocks debugger attachment.',
    severity: 'medium',
    relatedRules: ['M9', 'DEBUG', 'PTRACE'],
  },
  {
    id: 'code_obfuscation',
    label: 'Code Obfuscation',
    description: 'App uses obfuscated identifiers or string encryption.',
    severity: 'medium',
    relatedRules: ['OBFUSC', 'STRING_ENC'],
  },
  {
    id: 'anti_tamper',
    label: 'Integrity / Tamper Detection',
    description: 'App verifies its own signature or file hashes at runtime.',
    severity: 'high',
    relatedRules: ['M8', 'TAMPER', 'INTEGRITY'],
  },
  {
    id: 'emulator_detection',
    label: 'Emulator Detection',
    description: 'App detects when running inside an emulator or simulator.',
    severity: 'low',
    relatedRules: ['EMULATOR', 'VIRTUAL'],
  },
  {
    id: 'crypto_weak',
    label: 'Weak Cryptography',
    description: 'App uses outdated or broken cryptographic primitives.',
    severity: 'critical',
    relatedRules: ['M5', 'CRYPTO', 'DES', 'MD5', 'SHA1'],
  },
  {
    id: 'hardcoded_secrets',
    label: 'Hardcoded Secrets',
    description: 'App embeds credentials, keys, or tokens in its binary.',
    severity: 'critical',
    relatedRules: ['M1', 'SECRET', 'HARDCODED', 'KEY'],
  },
]

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const severityBadge: Record<string, string> = {
  critical: 'bg-chimera-critical text-white',
  high: 'bg-chimera-high text-black',
  medium: 'bg-chimera-medium text-black',
  low: 'bg-chimera-low text-white',
  info: 'bg-chimera-muted text-white',
}

function matchesProtection(finding: Finding, protection: Omit<ProtectionItem, 'detected'>): boolean {
  const haystack = [finding.rule_id, finding.title, finding.description ?? '']
    .join(' ')
    .toUpperCase()
  return protection.relatedRules.some((r) => haystack.includes(r.toUpperCase()))
}

export function ProtectionReport({ projectId }: Props) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [exportFormat, setExportFormat] = useState<'json' | 'markdown' | 'sarif'>('markdown')
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    setLoading(true)
    api
      .listFindings(projectId)
      .then((data) => setFindings(data.findings ?? []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false))
  }, [projectId])

  const protections: ProtectionItem[] = PROTECTION_CHECKS.map((p) => ({
    ...p,
    detected: findings.some((f) => matchesProtection(f, p)),
  })).sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])

  const detected = protections.filter((p) => p.detected)
  const missing = protections.filter((p) => !p.detected)

  function handleExport() {
    setExporting(true)
    api.exportReport(projectId, exportFormat)
      .then((text) => {
        const ext = exportFormat === 'sarif' ? 'sarif.json' : exportFormat === 'json' ? 'json' : 'md'
        const mime = exportFormat === 'markdown' ? 'text/markdown' : 'application/json'
        const blob = new Blob([text], { type: mime })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `chimera-report-${projectId.slice(0, 8)}.${ext}`
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(() => alert('Export failed'))
      .finally(() => setExporting(false))
  }

  if (loading) {
    return <div className="p-4 text-xs text-chimera-muted">Loading protection data...</div>
  }

  return (
    <div className="h-full overflow-y-auto bg-chimera-bg text-xs">
      {/* Header */}
      <div className="px-4 py-3 bg-chimera-surface border-b border-chimera-border flex items-center gap-4">
        <div>
          <div className="font-bold text-chimera-text text-sm">Protection Report</div>
          <div className="text-chimera-muted mt-0.5">
            {detected.length} / {protections.length} protections detected &middot;{' '}
            {findings.length} total findings
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <select
            value={exportFormat}
            onChange={(e) => setExportFormat(e.target.value as typeof exportFormat)}
            className="bg-chimera-panel border border-chimera-border text-chimera-text px-2 py-1 rounded text-xs"
          >
            <option value="markdown">Markdown</option>
            <option value="json">JSON</option>
            <option value="sarif">SARIF</option>
          </select>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="px-3 py-1 bg-chimera-accent text-black rounded text-xs font-semibold hover:opacity-90 disabled:opacity-50"
          >
            {exporting ? 'Exporting…' : 'Export Report'}
          </button>
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex gap-px mx-4 mt-4 rounded overflow-hidden h-3">
        {protections.map((p) => (
          <div
            key={p.id}
            style={{ flex: 1 }}
            className={p.detected ? 'bg-green-500' : 'bg-chimera-border'}
            title={p.label}
          />
        ))}
      </div>
      <div className="mx-4 mt-1 text-chimera-muted text-[10px]">
        Green = detected protection &middot; Grey = not detected (potential gap)
      </div>

      {/* Detected protections */}
      <div className="px-4 mt-4">
        <div className="text-chimera-muted font-semibold uppercase tracking-wide text-[10px] mb-2">
          Detected ({detected.length})
        </div>
        {detected.length === 0 && (
          <div className="text-chimera-muted italic">No known protections detected.</div>
        )}
        <div className="space-y-1">
          {detected.map((p) => (
            <div
              key={p.id}
              className="flex items-start gap-2 px-2 py-1.5 bg-chimera-surface rounded border border-chimera-border"
            >
              <span className="text-green-400 mt-0.5">✓</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-chimera-text">{p.label}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${severityBadge[p.severity]}`}>
                    {p.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-chimera-muted mt-0.5">{p.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Missing protections */}
      <div className="px-4 mt-4 mb-6">
        <div className="text-chimera-muted font-semibold uppercase tracking-wide text-[10px] mb-2">
          Not Detected — Potential Gaps ({missing.length})
        </div>
        {missing.length === 0 && (
          <div className="text-chimera-muted italic">All protections accounted for.</div>
        )}
        <div className="space-y-1">
          {missing.map((p) => (
            <div
              key={p.id}
              className="flex items-start gap-2 px-2 py-1.5 bg-chimera-surface/50 rounded border border-chimera-border/50 opacity-70"
            >
              <span className="text-chimera-muted mt-0.5">✗</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-chimera-muted">{p.label}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold opacity-60 ${severityBadge[p.severity]}`}>
                    {p.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-chimera-muted mt-0.5">{p.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
