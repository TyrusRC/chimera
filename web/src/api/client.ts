const BASE_URL = '/api'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
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

export interface ProjectDetail extends ProjectSummary {
  format: string
  framework: string
  function_count: number
  string_count: number
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

export interface Paginated<T> {
  total: number
  offset: number
  limit: number
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

  // Functions
  listFunctions: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<Paginated<FunctionSummary> & { functions: FunctionSummary[] }>(
      `/projects/${projectId}/functions${qs}`,
    )
  },
  getFunction: (projectId: string, address: string) =>
    request<FunctionDetail>(`/projects/${projectId}/functions/${address}`),
  getDisassembly: (projectId: string, address: string) =>
    request<{ address: string; name: string; instructions: Instruction[] }>(
      `/projects/${projectId}/functions/${address}/disassembly`,
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

  // Devices
  listDevices: () => request<DeviceEntry[]>('/devices'),

  // Export
  exportReport: (projectId: string, format: string) =>
    requestText(`/projects/${projectId}/export/${format}`),
}
