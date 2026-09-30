// Shared types derived from the ECDAT backend API (api.py v2.0.0)

export type Stats = {
  files_scanned?: number
  files_skipped?: number
  archives_opened?: number
  text_files?: number
  binary_files?: number
  duration_seconds?: number
  dependencies_found?: number
  container_manifests_found?: number
}

export type JobStatus = 'queued' | 'downloading' | 'scanning' | 'completed' | 'failed'

export type Job = {
  id: string
  source: string
  status: JobStatus
  stats: Stats
  error?: string
}

export type RiskProfile = {
  data_lifetime_years: number
  migration_time_years: number
  criticality: number
  crqc_arrival_years: number
}

export type RiskAssessment = {
  at_risk_now: boolean
  urgency_score: number | null
  risk_score: number
}

export type RawFinding = {
  file: string
  line: number | null
  offset: number | null
  pattern: string
  evidence: string
  kind: string
  severity: string
  confidence: string
  recommendation: string
}

export type Finding = RawFinding & {
  classification?: string
  quantum_vulnerable?: boolean
  riskAssessment?: RiskAssessment
  cryptoAgilityScore?: number
  metadata?: Record<string, unknown>
}

export type RiskSummary = {
  assets_assessed: number
  quantum_vulnerable_assets: number
  at_risk_now: number
  average_crypto_agility_score: number | null
}

export type Patch = {
  file: string
  changes: string[]
  diff: string[]
  review_required: boolean
}

export interface GraphNode {
  id: string
  label: string
  kind?: string
}
export interface GraphEdge {
  source: string
  target: string
}
export interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export type Report = {
  id: string
  source: string
  findings: Finding[]
  patches?: Patch[]
  stats: Stats
  warnings: string[]
  partial: boolean
  cbom: unknown
  profile: RiskProfile
  risk_summary?: RiskSummary
  audit_block_hash?: string
  audit_error?: string
  coverage?: Record<string, number>
  dependency_graphs?: Graph[]
}

export type ScanSummary = {
  id: string
  source: string
  timestamp?: string
  score?: number
  profile?: RiskProfile
  partial: boolean
  quantum_vulnerable?: number
  findings: number
  stats: Stats
}

export type AuditVerifyResult = {
  is_valid: boolean
  broken_index: number | null
  records: number
  reports_verified: number
  report_errors?: string[]
  error?: string
}
