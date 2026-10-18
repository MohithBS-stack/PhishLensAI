/**
 * PhishLens AI API Client & Type Definitions
 */

export interface SystemInfo {
  python_version: string;
  platform: string;
}

export interface HealthResponse {
  status: string;
  app_name: string;
  version: string;
  environment: string;
  timestamp: string;
  system: SystemInfo;
  models_loaded: Record<string, boolean>;
}

export interface NormalizedEvidence {
  evidence_id: string;
  source_modality: "text" | "url" | "screenshot" | "audio" | string;
  indicator_type: string;
  description: string;
  supporting_excerpt: string | null;
  severity: "low" | "medium" | "high" | "critical";
  evidence_source: string;
  confidence: number | null;
  observed_versus_inferred: "observed" | "inferred";
  limitations_and_missing_checks: string[];
}

export interface ManipulationTactic {
  tactic_id: string;
  category:
    | "urgency"
    | "authority_impersonation"
    | "secrecy"
    | "credential_request"
    | "payment_request"
    | "identity_inconsistency"
    | string;
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  supporting_evidence: string;
  disclaimer: string;
}

export interface StructuredExplanation {
  summary: string;
  executive_brief: string;
  key_concerns: string[];
  manipulation_tactics_explained: string[];
  remediation_advice: string[];
  is_llm_generated: boolean;
  model_name: string | null;
}

export interface UncertaintyReport {
  is_uncertain: boolean;
  uncertainty_level: "low" | "medium" | "high";
  reasons: string[];
  calibration_disclosure: string;
  conflicting_signals: string[];
}

export interface ModelSignals {
  model_a_sms_classifier?: {
    active: boolean;
    label: string | null;
    spam_probability: number | null;
    confidence: number | null;
    points_contributed: number;
  };
  model_b_url_classifier?: {
    active: boolean;
    urls_scanned_count: number;
    any_phishing: boolean;
    max_phishing_probability: number;
    points_contributed: number;
  };
  heuristics_and_tactics?: {
    categories_detected: string[];
    raw_tactic_points: number;
    capped_tactic_points: number;
    correlation_dampening_applied: number;
  };
  weights_configuration?: {
    weight_model_a_max: number;
    weight_model_b_phish_max: number;
    weight_tactics_max: number;
    threshold_high: number;
    threshold_suspicious: number;
  };
}

export interface UnifiedReportResponse {
  case_id: string;
  verdict: "benign" | "suspicious" | "high-risk" | "inconclusive";
  score: number;
  evidence_by_modality: Record<string, NormalizedEvidence[]>;
  all_evidence: NormalizedEvidence[];
  manipulation_tactics: ManipulationTactic[];
  supporting_excerpts: string[];
  model_signals: ModelSignals;
  missing_checks: string[];
  uncertainty: UncertaintyReport;
  safe_next_steps: string[];
  explanation: StructuredExplanation;
  timestamp?: string; // Populated locally for history tracking
}

export interface UnifiedScanPayload {
  text?: string;
  urls?: string[];
  include_explanation?: boolean;
}

export interface ThreatIndicator {
  indicator_type: string;
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  evidence: string | null;
}

export interface URLScanResponse {
  url: string;
  is_phishing: boolean;
  confidence: number;
  label: string;
  phishing_probability: number;
  risk_score: number;
  severity: string;
  extracted_features: Record<string, unknown>;
  threat_indicators: ThreatIndicator[];
  explanation: StructuredExplanation | null;
}

export interface URLScanPayload {
  url: string;
  include_explanation?: boolean;
}

/**
 * Resolves the API base URL safely across environments.
 *
 * In production browser environments, relative same-origin URLs ("") are strictly enforced
 * so browser requests route through the Next.js same-origin proxy, preventing accidental
 * proxy bypass and cross-site third-party cookie blocking.
 */
export function resolveApiBaseUrl(
  rawEnvUrl?: string,
  isProduction: boolean = process.env.NODE_ENV === "production",
  isBrowser: boolean = typeof window !== "undefined"
): string {
  if (isProduction && isBrowser) {
    return "";
  }
  const trimmed = (rawEnvUrl || "").trim().replace(/\/+$/, "");
  return trimmed || "";
}

export const API_BASE_URL = resolveApiBaseUrl(process.env.NEXT_PUBLIC_API_URL);


const DEFAULT_TIMEOUT_MS = 20000;
const HEALTH_TIMEOUT_MS = 25000;

/**
 * Health check endpoint
 */
export async function fetchHealth(): Promise<HealthResponse> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${API_BASE_URL}/health`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(id);
    if (!res.ok) {
      throw new Error(`Backend returned HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err: unknown) {
    clearTimeout(id);
    const msg = err instanceof Error ? err.message : "Network error";
    throw new Error(msg);
  }
}

/**
 * Unified JSON scan (Text + URLs)
 */
export async function scanUnified(
  payload: UnifiedScanPayload,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<UnifiedReportResponse> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/scan/unified`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(id);

    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      const message =
        errData?.error?.message ||
        `Investigation failed with HTTP ${res.status}`;
      throw new Error(message);
    }

    const data: UnifiedReportResponse = await res.json();
    data.timestamp = new Date().toISOString();
    return data;
  } catch (err: unknown) {
    clearTimeout(id);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Request timed out. The backend took too long to analyze the submission.");
    }
    const msg = err instanceof Error ? err.message : "Investigation failed";
    throw new Error(msg);
  }
}

/**
 * Multimodal investigation (Text, URLs, Screenshot file, Audio file)
 */
export async function investigateMultimodal(
  formData: FormData,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<UnifiedReportResponse> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/scan/investigate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      body: formData,
      signal: controller.signal,
    });
    clearTimeout(id);

    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      const message =
        errData?.error?.message ||
        `Multimodal investigation failed with HTTP ${res.status}`;
      throw new Error(message);
    }

    const data: UnifiedReportResponse = await res.json();
    data.timestamp = new Date().toISOString();
    return data;
  } catch (err: unknown) {
    clearTimeout(id);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Request timed out during multimodal processing.");
    }
    const msg = err instanceof Error ? err.message : "Multimodal analysis failed";
    throw new Error(msg);
  }
}

/**
 * Direct URL scan with optional explanation
 */
export async function scanUrl(
  payload: URLScanPayload,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<URLScanResponse> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/scan/url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(id);

    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      const message =
        errData?.error?.message ||
        `URL scan failed with HTTP ${res.status}`;
      throw new Error(message);
    }

    return await res.json();
  } catch (err: unknown) {
    clearTimeout(id);
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Request timed out during URL analysis.");
    }
    const msg = err instanceof Error ? err.message : "URL scan failed";
    throw new Error(msg);
  }
}
