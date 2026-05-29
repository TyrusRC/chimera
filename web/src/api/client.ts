const BASE_URL = '/api'

async function request<T>(path: string, options?: RequestInit & { signal?: AbortSignal }): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(error.detail || res.statusText)
  }
  return res.json()
}

async function requestText(path: string): Promise<string> {
  const res = await fetch(`${BASE_URL}${path}`)
  if (!res.ok) {
    throw new Error(res.statusText)
  }
  return res.text()
}

// ---------- Shared response types ----------

export interface ProjectSummary {
  id: string
  name: string
  platform: string
  status: string
  finding_count: number
}

export interface ProjectCapabilities {
  frida: boolean
  masvs: boolean
  manifest: boolean
  network_security_config: boolean
  dotnet: boolean
  objc: boolean
}

export interface ProjectDetail extends ProjectSummary {
  format: string
  framework: string
  function_count: number
  string_count: number
  capabilities: ProjectCapabilities
}

export interface FunctionSummary {
  address: string
  name: string
  original_name: string
  language: string
  classification: string
  layer: string
  source_backend: string
  has_decompiled: boolean
}

export interface FunctionDetail extends FunctionSummary {
  decompiled: string | null
  signature: string | null
  callees: { address: string; name: string }[]
  callers: { address: string; name: string }[]
}

export interface StringEntry {
  address: string
  value: string
  section: string | null
  decrypted_from: string | null
}

export interface FindingEntry {
  rule_id: string
  severity: string
  confidence: string
  status: string
  title: string
  description: string
  location: string
  evidence_static: string | null
  evidence_dynamic: string | null
  masvs_category: string | null
  mastg_test: string | null
  business_impact: string | null
  poc: string | null
  detected_at: string
  confirmed_at: string | null
}

export interface Paginated<_T> {
  total: number
  offset: number
  limit: number
}

export interface DiffFinding {
  finding_id: string | null
  title: string | null
  severity: string | null
  cvss_vector: string | null
  cvss_base_score: number | null
  evidence: string[]
}

export interface DiffComponent {
  kind: string | null
  name: string | null
  exported: boolean | null
  has_intent_filter: boolean | null
}

export interface DiffNativeLib {
  lib: string | null
  kind: string | null
  detail: string | null
}

export interface DiffResult {
  a_sha256: string
  b_sha256: string
  permissions_added: string[]
  permissions_removed: string[]
  exported_added: DiffComponent[]
  exported_removed: DiffComponent[]
  sdks_added: string[]
  sdks_removed: string[]
  native_libs_added: DiffNativeLib[]
  native_libs_removed: DiffNativeLib[]
  native_libs_changed: DiffNativeLib[]
  findings_added: DiffFinding[]
  findings_resolved: DiffFinding[]
}

export interface CallGraphData {
  nodes: { id: string; name: string; classification: string; layer: string }[]
  edges: { source: string; target: string; type: string }[]
  center: string
}

export interface Instruction {
  address: string
  mnemonic: string
  operands: string
  bytes: string
  comment?: string
}

export interface DeviceEntry {
  id: string
  platform: string
  model: string | null
  os_version: string | null
  is_rooted: boolean
  is_jailbroken: boolean
}

export interface BackendEntry {
  name: string
  available: boolean
  formats: string[]
}

export interface FridaScriptMeta {
  id: string
  name: string
  description: string
  platform: string
  requires: string[]
  risk: string
  file: string
}

export interface FridaSessionInfo {
  id: string
  device_id: string | null
  target: string
  mode: string
  pid: number | null
}

// ---------- API methods ----------

export const api = {
  // System
  getInfo: () => request<{ name: string; version: string }>('/info'),
  getBackends: () => request<BackendEntry[]>('/backends'),

  // Projects
  listProjects: () => request<ProjectSummary[]>('/projects'),
  createProject: (path: string) =>
    request<{ id: string; status: string }>('/projects', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  getProject: (id: string) => request<ProjectDetail>(`/projects/${id}`),
  uploadProject: async (file: File): Promise<{ path: string; filename: string; size: number }> => {
    const fd = new FormData()
    fd.append('file', file)
    const res = await fetch(`${BASE_URL}/projects/upload`, { method: 'POST', body: fd })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || res.statusText)
    }
    return res.json()
  },

  // Functions
  listFunctions: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<Paginated<FunctionSummary> & { functions: FunctionSummary[] }>(
      `/projects/${projectId}/functions${qs}`,
    )
  },
  getFunction: (projectId: string, address: string, signal?: AbortSignal) =>
    request<FunctionDetail>(`/projects/${projectId}/functions/${address}`, { signal }),
  getDisassembly: (projectId: string, address: string, signal?: AbortSignal) =>
    request<{ address: string; name: string; instructions: Instruction[] }>(
      `/projects/${projectId}/functions/${address}/disassembly`,
      { signal },
    ),

  // Raw bytes (hex view)
  getBytes: (projectId: string, offset: number, length: number, signal?: AbortSignal) =>
    request<{ offset: number; length: number; hex: string; total_size: number }>(
      `/projects/${projectId}/bytes?offset=${offset}&length=${length}`,
      { signal },
    ),

  // Strings
  listStrings: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<Paginated<StringEntry> & { strings: StringEntry[] }>(
      `/projects/${projectId}/strings${qs}`,
    )
  },

  // Findings
  listFindings: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<Paginated<FindingEntry> & { findings: FindingEntry[] }>(
      `/projects/${projectId}/findings${qs}`,
    )
  },

  // Call graph
  getCallGraph: (projectId: string, address: string, depth = 2) =>
    request<CallGraphData>(`/projects/${projectId}/callgraph/${address}?depth=${depth}`),

  // Diff
  diffProjects: (a: string, b: string, signal?: AbortSignal) =>
    request<DiffResult>('/diff', {
      method: 'POST',
      body: JSON.stringify({ a, b }),
      signal,
    }),

  // Devices
  listDevices: () => request<DeviceEntry[]>('/devices'),
  listPackages: (deviceId: string, signal?: AbortSignal) =>
    request<{ packages: string[] }>(`/devices/${deviceId}/packages`, { signal }),

  // Frida
  listFridaScripts: (signal?: AbortSignal) =>
    request<{ scripts: FridaScriptMeta[] }>('/frida/scripts', { signal }),
  listFridaSessions: () =>
    request<{ sessions: FridaSessionInfo[] }>('/frida/sessions'),
  createFridaSession: (body: { device_id?: string; target: string; mode: 'attach' | 'spawn' }) =>
    request<{ session_id: string }>('/frida/sessions', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  execFrida: (sessionId: string, code: string) =>
    request<{ result: string }>(`/frida/sessions/${sessionId}/exec`, {
      method: 'POST',
      body: JSON.stringify({ code }),
    }),
  loadFridaScript: (sessionId: string, body: { script_id?: string; source?: string }) =>
    request<{ ok: boolean }>(`/frida/sessions/${sessionId}/load`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  closeFridaSession: (sessionId: string) =>
    request<{ ok: boolean }>(`/frida/sessions/${sessionId}`, { method: 'DELETE' }),

  // Export
  exportReport: (projectId: string, format: string) =>
    requestText(`/projects/${projectId}/export/${format}`),

  // Annotations — analyst renames / comments / types persisted per binary.
  listAnnotations: (projectId: string) =>
    request<{
      function_names: Record<string, string>
      variable_renames: Record<string, Record<string, string>>
      comments: Record<string, Record<string, string>>
      function_types: Record<string, string>
    }>(`/projects/${projectId}/annotations`),
  renameAnnotation: (projectId: string, body: {
    kind: 'function' | 'variable'
    address: string
    new_name: string
    original?: string
  }) => request<{ ok: boolean }>(`/projects/${projectId}/annotations/rename`, {
    method: 'POST',
    body: JSON.stringify(body),
  }),
  commentAnnotation: (projectId: string, body: { address: string; text: string; line?: number }) =>
    request<{ ok: boolean }>(`/projects/${projectId}/annotations/comment`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  typeAnnotation: (projectId: string, body: { address: string; signature: string }) =>
    request<{ ok: boolean }>(`/projects/${projectId}/annotations/type`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  deleteRenameAnnotation: (projectId: string, address: string) =>
    request<{ ok: boolean }>(`/projects/${projectId}/annotations/rename/${address}`, {
      method: 'DELETE',
    }),

  // Decompilation — multi-backend, post-processed for readability.
  getDecomp: (projectId: string, address: string, backend: 'r2' | 'ghidra' | 'all', signal?: AbortSignal) =>
    request<DecompResponse>(
      `/projects/${projectId}/functions/${address}/decomp?backend=${backend}`,
      { signal },
    ),

  // AI — Claude-backed explain/rename/comment. 503 when ANTHROPIC_API_KEY unset.
  aiStatus: (projectId: string) =>
    request<{ available: boolean; model: string | null }>(`/projects/${projectId}/ai/status`),
  aiExplain: (projectId: string, address: string, backend: 'r2' | 'ghidra' = 'r2') =>
    request<{ address: string; name: string; explanation: string; model: string }>(
      `/projects/${projectId}/ai/explain`,
      { method: 'POST', body: JSON.stringify({ address, backend }) },
    ),
  aiRename: (projectId: string, address: string, backend: 'r2' | 'ghidra' = 'r2') =>
    request<{ address: string; current_name: string; suggested_name: string; model: string }>(
      `/projects/${projectId}/ai/rename`,
      { method: 'POST', body: JSON.stringify({ address, backend }) },
    ),
  aiComment: (projectId: string, address: string, line: number, backend: 'r2' | 'ghidra' = 'r2') =>
    request<{ address: string; name: string; line: number; comment: string; model: string }>(
      `/projects/${projectId}/ai/comment`,
      { method: 'POST', body: JSON.stringify({ address, line, backend }) },
    ),

  // Overlay — portable annotation export/import for analyst-to-analyst sharing.
  exportOverlay: (projectId: string) =>
    request<{
      schema: string
      sha256: string
      function_names: Record<string, string>
      variable_renames: Record<string, Record<string, string>>
      comments: Record<string, Record<string, string>>
      function_types: Record<string, string>
      user_classifications: Record<string, string>
    }>(`/projects/${projectId}/overlay/export`),
  importOverlay: (projectId: string, payload: unknown, mode: 'merge' | 'replace' = 'merge') =>
    request<{ ok: boolean; mode: string; warnings: string[]; counts: Record<string, number> }>(
      `/projects/${projectId}/overlay/import`,
      { method: 'POST', body: JSON.stringify({ payload, mode }) },
    ),

  // Function similarity — BinDiff-style two-binary diff at function granularity.
  diffFunctions: (a: string, b: string, threshold = 0.85) =>
    request<{
      threshold: number
      totals: Record<string, number>
      matched: Array<{ a_address: string; b_address: string; a_name: string; b_name: string; similarity: number; fingerprint: string }>
      changed: Array<{ a_address: string; b_address: string; a_name: string; b_name: string; similarity: number; fingerprint: string }>
      added: Array<{ address: string; name: string }>
      removed: Array<{ address: string; name: string }>
    }>(`/diff/functions`, {
      method: 'POST',
      body: JSON.stringify({ a, b, threshold }),
    }),
}

export interface DecompResponse {
  address: string
  name: string
  backends: Record<string, { ok: boolean; code: string; lines: number; error?: string }>
}
