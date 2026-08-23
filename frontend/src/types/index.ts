// TypeScript shared types for ThreatLens AI frontend

// ── Authentication ────────────────────────────────────────────────────────────
export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string | null;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

// ── Threat Events ─────────────────────────────────────────────────────────────
export type ThreatSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ThreatStatus =
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "false_positive";

export interface ThreatEvent {
  id: number;
  title: string;
  description: string | null;
  severity: ThreatSeverity;
  status: ThreatStatus;
  threat_type: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  affected_asset: string | null;
  cve_id: string | null;
  cvss_score: number | null;
  ai_confidence: number | null;
  ai_recommendation: string | null;
  is_resolved: boolean;
  reported_by_id: number | null;
  assigned_to_id: number | null;
  detected_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface ThreatListResponse {
  items: ThreatEvent[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export interface ThreatStats {
  total: number;
  open: number;
  critical: number;
  resolved: number;
  severity_breakdown: Record<ThreatSeverity, number>;
  classification_counts?: Record<string, number>;
}

export interface IncidentReport {
  timestamp: string;
  target_name: string;
  classification: string;
  confidence: string;
  action_taken: string;
  status: string;
  md5_hash?: string;
  sha256_hash?: string;
  risk_score?: number;
  detected_indicators?: string[];
  file_size?: string; // only present for real file uploads
}

export interface ScanResultResponse {
  alert_message: string;
  notification_sent: boolean;
  analyst_response: string;
  incident_report: IncidentReport;
  threat_event: ThreatEvent;
}

export interface ThreatCreate {
  title: string;
  severity: ThreatSeverity;
  description?: string;
  threat_type?: string;
  source_ip?: string;
  destination_ip?: string;
  affected_asset?: string;
  cve_id?: string;
  cvss_score?: number;
}

export interface ThreatUpdate {
  status?: ThreatStatus;
  assigned_to_id?: number;
  ai_confidence?: number;
  ai_recommendation?: string;
  is_resolved?: boolean;
}

// ── API Errors ────────────────────────────────────────────────────────────────
export interface APIError {
  detail: string | { msg: string; type: string }[];
  status_code?: number;
}

// ── Pagination ────────────────────────────────────────────────────────────────
export interface PaginationParams {
  page?: number;
  size?: number;
  severity?: ThreatSeverity;
  status?: ThreatStatus;
  search?: string;
}
