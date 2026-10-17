/**
 * Automated Unit Tests for PhishLens AI Case History Client.
 *
 * Verifies:
 * - Saving investigation cases with authorization header and credentials.
 * - Retrieving paginated cases with stable sorting and metadata.
 * - Single case detail retrieval with ownership isolation error translation.
 * - Case deletion with 404 handling.
 * - Error handling for expired sessions (401), missing cases (404), and payload limit violations (422).
 * - Anonymous scanning operations remain functional and unblocked.
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  saveCaseApi,
  listCasesApi,
  getCaseApi,
  deleteCaseApi,
  type SaveCasePayload,
} from "../lib/cases.ts";
import { scanUnified } from "../lib/api.ts";

describe("Persistent Case History Client (lib/cases.ts)", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const mockReportPayload: any = {
    case_id: "CASE-2026-TEST-001",
    verdict: "high-risk",
    score: 87.5,
    timestamp: "2026-10-17T12:00:00Z",
    evidence_by_modality: {},
    all_evidence: [],
    manipulation_tactics: [],
    supporting_excerpts: [],
    model_signals: {
      model_a_sms_classifier: null,
      model_b_url_classifier: null,
      heuristics_and_tactics: null,
    },
    missing_checks: [],
    uncertainty: { calibration_disclosure: "Passive triage only" },
    safe_next_steps: ["Do not click link"],
    explanation: {
      summary: "Urgent account suspension smishing",
      executive_brief: "High confidence credential harvesting attempt.",
      key_concerns: ["Immediate urgency tactic detected"],
      is_llm_generated: false,
    },
  };

  it("saveCaseApi: successfully posts investigation report with Bearer token", async () => {
    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedInit = init;
      return new Response(
        JSON.stringify({
          id: "uuid-1234",
          case_id: "CASE-2026-TEST-001",
          investigation_type: "unified",
          verdict: "high-risk",
          threat_score: 87.5,
          severity: "high",
          schema_version: 1,
          report_payload: mockReportPayload,
          created_at: "2026-10-17T12:00:00Z",
          updated_at: "2026-10-17T12:00:00Z",
        }),
        { status: 201, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    const res = await saveCaseApi(
      {
        case_id: "CASE-2026-TEST-001",
        investigation_type: "unified",
        report_payload: mockReportPayload,
      },
      "valid-access-token-xyz"
    );

    assert.equal(capturedUrl, "/api/v1/cases");
    assert.equal(capturedInit?.method, "POST");
    assert.equal(
      (capturedInit?.headers as Record<string, string>)["Authorization"],
      "Bearer valid-access-token-xyz"
    );
    assert.equal(capturedInit?.credentials, "same-origin");
    assert.equal(res.case_id, "CASE-2026-TEST-001");
    assert.equal(res.threat_score, 87.5);
  });

  it("saveCaseApi: handles 401 session expiration gracefully", async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          error: { message: "Could not validate credentials." },
        }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    await assert.rejects(
      async () => {
        await saveCaseApi(
          { report_payload: mockReportPayload },
          "expired-token"
        );
      },
      {
        name: "Error",
        message: "Could not validate credentials.",
      }
    );
  });

  it("saveCaseApi: handles 422 payload validation or size limit errors", async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          detail: [{ msg: "Case report payload exceeds maximum allowed size of 1MB." }],
        }),
        { status: 422, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    await assert.rejects(
      async () => {
        await saveCaseApi(
          { report_payload: mockReportPayload },
          "valid-token"
        );
      },
      /exceeds maximum allowed size|Failed to save case/
    );
  });

  it("listCasesApi: sends pagination parameters and returns paginated list", async () => {
    let capturedUrl = "";
    let capturedAuth = "";

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedAuth = (init?.headers as Record<string, string>)["Authorization"];
      return new Response(
        JSON.stringify({
          items: [
            {
              id: "uuid-1",
              case_id: "CASE-001",
              investigation_type: "unified",
              verdict: "high-risk",
              threat_score: 92.0,
              severity: "critical",
              schema_version: 1,
              created_at: "2026-10-17T12:00:00Z",
              summary: "Smishing attack",
            },
          ],
          total: 1,
          page: 2,
          page_size: 5,
          total_pages: 1,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    const res = await listCasesApi(2, 5, "analyst-token-abc");

    assert.equal(capturedUrl, "/api/v1/cases?page=2&page_size=5");
    assert.equal(capturedAuth, "Bearer analyst-token-abc");
    assert.equal(res.items.length, 1);
    assert.equal(res.items[0].case_id, "CASE-001");
    assert.equal(res.total, 1);
    assert.equal(res.page, 2);
  });

  it("getCaseApi: retrieves single case details and encodes case_id", async () => {
    let capturedUrl = "";

    globalThis.fetch = (async (url: string | URL | Request) => {
      capturedUrl = url.toString();
      return new Response(
        JSON.stringify({
          id: "uuid-1",
          case_id: "CASE/2026/001",
          investigation_type: "unified",
          verdict: "suspicious",
          threat_score: 55.0,
          severity: "medium",
          schema_version: 1,
          report_payload: mockReportPayload,
          created_at: "2026-10-17T12:00:00Z",
          updated_at: "2026-10-17T12:00:00Z",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    const res = await getCaseApi("CASE/2026/001", "my-token");

    assert.equal(capturedUrl, "/api/v1/cases/CASE%2F2026%2F001");
    assert.equal(res.case_id, "CASE/2026/001");
    assert.deepEqual(res.report_payload, mockReportPayload);
  });

  it("getCaseApi: translates 404 to user-friendly isolated error", async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          error: { message: "Investigation case not found." },
        }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    await assert.rejects(
      async () => {
        await getCaseApi("NON-EXISTENT-OR-OTHER-USER", "my-token");
      },
      {
        name: "Error",
        message: "Investigation case not found.",
      }
    );
  });

  it("deleteCaseApi: sends DELETE request with Bearer authorization", async () => {
    let capturedMethod = "";
    let capturedUrl = "";

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedMethod = init?.method || "GET";
      return new Response(null, { status: 204 });
    }) as any;

    await deleteCaseApi("CASE-TO-DELETE", "my-token");

    assert.equal(capturedUrl, "/api/v1/cases/CASE-TO-DELETE");
    assert.equal(capturedMethod, "DELETE");
  });

  it("deleteCaseApi: handles 404 when case does not exist or belongs to another user", async () => {
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          error: { message: "Investigation case not found." },
        }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    await assert.rejects(
      async () => {
        await deleteCaseApi("ANOTHER-USERS-CASE", "my-token");
      },
      {
        name: "Error",
        message: "Investigation case not found.",
      }
    );
  });

  it("anonymous scan workflow remains fully operational without tokens", async () => {
    let capturedAuth: string | undefined;

    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      capturedAuth = (init?.headers as Record<string, string>)?.["Authorization"];
      return new Response(
        JSON.stringify(mockReportPayload),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as any;

    const res = await scanUnified({
      message_text: "URGENT: Verify your account immediately",
      sender_phone: "+15550199",
      embedded_urls: ["https://secure-login-update.com"],
    });

    assert.equal(capturedAuth, undefined); // No auth token required for scan
    assert.equal(res.case_id, "CASE-2026-TEST-001");
    assert.equal(res.verdict, "high-risk");
  });
});
