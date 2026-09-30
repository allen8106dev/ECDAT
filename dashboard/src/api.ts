// API utilities — wraps fetch with timeout + typed errors
import type { Job, Report, ScanSummary, AuditVerifyResult } from './types'

export const API = import.meta.env.VITE_API_URL || '/api'

async function jsonResponse(response: Response) {
  const data = await response.json().catch(() => {
    throw new Error(`Scanner returned an invalid response (HTTP ${response.status}). Check the API connection.`)
  })
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))
  return data
}

export async function requestJson<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const timeout = new AbortController()
  const timer = setTimeout(() => timeout.abort(), 15000)
  const abort = () => timeout.abort()
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted) timeout.abort()
  try {
    return await fetch(`${API}${path}`, { ...options, signal: timeout.signal }).then(jsonResponse) as T
  } catch (error) {
    if (timeout.signal.aborted && !options.signal?.aborted) {
      throw new Error('The scanner did not respond within 15 seconds. Check the backend connection and retry.')
    }
    throw error
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abort)
  }
}

export function validateJob(value: unknown): Job {
  const job = value as Partial<Job> | null
  if (!job || typeof job.id !== 'string' || !/^[a-f0-9]{32}$/.test(job.id) ||
      !['queued', 'downloading', 'scanning', 'completed', 'failed'].includes(job.status || '') ||
      typeof job.source !== 'string' || !job.stats || typeof job.stats !== 'object') {
    throw new Error('The dashboard is connected to an outdated or incompatible backend. Restart the ECDAT backend and refresh.')
  }
  return job as Job
}

export function triggerDownload(url: string, name: string) {
  const link = document.createElement('a'); link.href = url; link.download = name; link.click()
}

export function profileParams(profile: { data_lifetime_years: number; migration_time_years: number; criticality: number; crqc_arrival_years: number }, scanMode: string) {
  return new URLSearchParams([
    ...Object.entries(profile).map(([k, v]) => [k, String(v)]),
    ['scan_mode', scanMode],
  ]).toString()
}

// Convenience wrappers
export async function fetchJob(id: string, signal?: AbortSignal): Promise<Job> {
  return validateJob(await requestJson(`/scans/${id}`, { signal }))
}

export async function fetchReport(id: string, signal?: AbortSignal): Promise<Report> {
  return requestJson<Report>(`/scans/${id}/result?include_cbom=false`, { signal })
}

export async function fetchHistory(limit = 50): Promise<ScanSummary[]> {
  const data = await requestJson<{ scans: ScanSummary[] }>(`/history?limit=${limit}`)
  return data.scans
}

export async function verifyAudit(): Promise<AuditVerifyResult> {
  return requestJson<AuditVerifyResult>('/audit/verify')
}

export async function checkHealth(): Promise<{ version: string }> {
  return requestJson<{ version: string }>('/')
}
