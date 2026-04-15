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

export const api = {
  getInfo: () => request<{ name: string; version: string }>('/info'),
  getBackends: () => request<Array<{ name: string; available: boolean }>>('/backends'),

  listProjects: () => request<Array<any>>('/projects'),
  createProject: (path: string) =>
    request<{ id: string; status: string }>('/projects', {
      method: 'POST',
      body: JSON.stringify({ path }),
    }),
  getProject: (id: string) => request<any>(`/projects/${id}`),

  listFunctions: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<any>(`/projects/${projectId}/functions${qs}`)
  },
  getFunction: (projectId: string, address: string) =>
    request<any>(`/projects/${projectId}/functions/${address}`),

  listStrings: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<any>(`/projects/${projectId}/strings${qs}`)
  },

  listFindings: (projectId: string, params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<any>(`/projects/${projectId}/findings${qs}`)
  },
}
