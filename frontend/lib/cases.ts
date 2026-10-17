/**
 * PhishLens AI — Persistent Case History Client
 *
 * Provides authenticated API calls for saving, retrieving, listing, and deleting
 * private forensic investigation reports via the same-origin Next.js proxy.
 */

import { API_BASE_URL, type UnifiedReportResponse } from "./api.ts";

export interface CaseSummary {
  id: string;
  case_id: string;
  investigation_type: string;
  verdict: "benign" | "suspicious" | "high-risk" | "inconclusive" | string;
  threat_score: number;
  severity: "low" | "medium" | "high" | "critical" | string;
  schema_version: number;
  created_at: string;
  summary: string | null;
}

export interface CaseDetail {
  id: string;
  case_id: string;
  investigation_type: string;
  verdict: "benign" | "suspicious" | "high-risk" | "inconclusive" | string;
  threat_score: number;
  severity: "low" | "medium" | "high" | "critical" | string;
  schema_version: number;
  report_payload: UnifiedReportResponse;
  created_at: string;
  updated_at: string;
}

export interface CaseListResponse {
  items: CaseSummary[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface SaveCasePayload {
  case_id?: string;
  investigation_type?: string;
  report_payload: UnifiedReportResponse;
}

/**
 * Saves an investigation case to the authenticated operator's private database ledger.
 */
export async function saveCaseApi(
  payload: SaveCasePayload,
  token: string
): Promise<CaseDetail> {
  const res = await fetch(`${API_BASE_URL}/api/v1/cases`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
    credentials: "same-origin",
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 401
        ? "Authentication session expired. Please sign in again."
        : res.status === 422
        ? "Invalid case payload or payload exceeds maximum allowed size."
        : `Failed to save case (HTTP ${res.status}).`);
    throw new Error(msg);
  }

  return (await res.json()) as CaseDetail;
}

/**
 * Lists paginated private investigation cases for the authenticated operator.
 */
export async function listCasesApi(
  page = 1,
  pageSize = 10,
  token: string
): Promise<CaseListResponse> {
  const res = await fetch(
    `${API_BASE_URL}/api/v1/cases?page=${page}&page_size=${pageSize}`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      credentials: "same-origin",
    }
  );

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 401
        ? "Session expired. Sign in to access your case ledger."
        : `Failed to retrieve cases (HTTP ${res.status}).`);
    throw new Error(msg);
  }

  return (await res.json()) as CaseListResponse;
}

/**
 * Retrieves full detail and report payload for a specific case owned by the user.
 */
export async function getCaseApi(
  caseId: string,
  token: string
): Promise<CaseDetail> {
  const res = await fetch(
    `${API_BASE_URL}/api/v1/cases/${encodeURIComponent(caseId)}`,
    {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      credentials: "same-origin",
    }
  );

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 404
        ? "Investigation case not found or not accessible."
        : `Failed to retrieve case (HTTP ${res.status}).`);
    throw new Error(msg);
  }

  return (await res.json()) as CaseDetail;
}

/**
 * Deletes an investigation case owned by the authenticated operator.
 */
export async function deleteCaseApi(
  caseId: string,
  token: string
): Promise<void> {
  const res = await fetch(
    `${API_BASE_URL}/api/v1/cases/${encodeURIComponent(caseId)}`,
    {
      method: "DELETE",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      },
      credentials: "same-origin",
    }
  );

  if (!res.ok) {
    const errData = await res.json().catch(() => null);
    const msg =
      errData?.error?.message ||
      (res.status === 404
        ? "Investigation case not found or already deleted."
        : `Failed to delete case (HTTP ${res.status}).`);
    throw new Error(msg);
  }
}
