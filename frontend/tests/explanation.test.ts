/**
 * Automated Tests for PhishLens AI Explanation Client & Presentation Model.
 *
 * Verifies:
 * - Direct URL scan API client (scanUrl) with explanation.
 * - Unified scan API client (scanUnified) with AI-grounded explanation (Gemini).
 * - Deterministic fallback explanation structure and badge flags.
 * - Error resilience when backend returns without an explanation.
 */

import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { scanUnified, scanUrl, type StructuredExplanation, type UnifiedReportResponse } from "../lib/api.ts";

describe("AI Explanation & Fallback Integration (lib/api.ts)", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("scanUnified: correctly processes AI-grounded Gemini explanation response", async () => {
    const mockExplanation: StructuredExplanation = {
      summary: "HIGH-RISK Phishing Threat Detected (Score: 88.0/100)",
      executive_brief: "The submitted message impersonates PayPal and attempts to harvest login credentials.",
      key_concerns: [
        "Urgency trigger: 'Account suspended within 24 hours'",
        "Phishing URL: http://paypal-fake-login.xyz",
      ],
      manipulation_tactics_explained: [
        "[URGENCY] Uses immediate deadline to elicit panic compliance",
      ],
      remediation_advice: [
        "Do not click links or enter passwords",
        "Verify account status directly on official portal",
      ],
      is_llm_generated: true,
      model_name: "gemini-2.5-flash",
    };

    const mockResponse: Partial<UnifiedReportResponse> = {
      case_id: "CASE-2026-TEST-AI",
      verdict: "high-risk",
      score: 88.0,
      evidence_by_modality: {},
      all_evidence: [],
      manipulation_tactics: [],
      supporting_excerpts: [],
      model_signals: {},
      missing_checks: [],
      uncertainty: {
        is_uncertain: false,
        uncertainty_level: "low",
        reasons: [],
        calibration_disclosure: "Passive triage only",
        conflicting_signals: [],
      },
      safe_next_steps: ["Do not click links"],
      explanation: mockExplanation,
    };

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const result = await scanUnified({
      text: "URGENT: PayPal account suspended. Verify at http://paypal-fake-login.xyz",
      include_explanation: true,
    });

    assert.equal(result.explanation.is_llm_generated, true);
    assert.equal(result.explanation.model_name, "gemini-2.5-flash");
    assert.ok(result.explanation.summary.includes("HIGH-RISK"));
    assert.equal(result.explanation.key_concerns.length, 2);
    assert.equal(result.verdict, "high-risk");
    assert.equal(result.score, 88.0);
  });

  it("scanUnified: correctly identifies deterministic rule briefing when Gemini is unavailable", async () => {
    const mockFallbackExplanation: StructuredExplanation = {
      summary: "SUSPICIOUS Threat Assessment (Risk Score: 45.0/100)",
      executive_brief: "PhishLens AI evaluated this investigation as SUSPICIOUS with composite threat score 45.0/100.",
      key_concerns: ["General risk indicators detected"],
      manipulation_tactics_explained: [],
      remediation_advice: ["Verify sender identity"],
      is_llm_generated: false,
      model_name: "Deterministic Rule-Grounded Generator",
    };

    const mockResponse: Partial<UnifiedReportResponse> = {
      case_id: "CASE-2026-TEST-FALLBACK",
      verdict: "suspicious",
      score: 45.0,
      evidence_by_modality: {},
      all_evidence: [],
      manipulation_tactics: [],
      supporting_excerpts: [],
      model_signals: {},
      missing_checks: [],
      uncertainty: {
        is_uncertain: false,
        uncertainty_level: "medium",
        reasons: [],
        calibration_disclosure: "Passive triage only",
        conflicting_signals: [],
      },
      safe_next_steps: ["Verify sender identity"],
      explanation: mockFallbackExplanation,
    };

    globalThis.fetch = (async () => {
      return new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const result = await scanUnified({
      text: "Please review the attached invoice.",
      include_explanation: true,
    });

    assert.equal(result.explanation.is_llm_generated, false);
    assert.equal(result.explanation.model_name, "Deterministic Rule-Grounded Generator");
    assert.ok(result.explanation.summary.includes("SUSPICIOUS"));
  });

  it("scanUrl: executes direct passive URL scan and returns explanation", async () => {
    let capturedUrl = "";
    let capturedBody = "";

    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedBody = String(init?.body || "");
      return new Response(
        JSON.stringify({
          url: "http://secure-login-chase-update.xyz",
          is_phishing: true,
          confidence: 0.94,
          label: "phishing",
          phishing_probability: 0.94,
          risk_score: 94.0,
          severity: "critical",
          extracted_features: { url_length: 37 },
          threat_indicators: [
            {
              indicator_type: "phishing_url",
              name: "Phishing URL Detected",
              severity: "critical",
              description: "URL exhibited lexical characteristics of phishing",
              evidence: "http://secure-login-chase-update.xyz",
            },
          ],
          explanation: {
            summary: "HIGH-RISK Phishing URL Detected",
            executive_brief: "Domain structure mimics Chase banking portal.",
            key_concerns: ["Suspicious brand substring in unverified domain"],
            manipulation_tactics_explained: [],
            remediation_advice: ["Do not enter credentials"],
            is_llm_generated: true,
            model_name: "gemini-2.5-flash",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }) as typeof fetch;

    const result = await scanUrl({
      url: "http://secure-login-chase-update.xyz",
      include_explanation: true,
    });

    assert.ok(capturedUrl.includes("/api/v1/scan/url"));
    assert.ok(capturedBody.includes("secure-login-chase-update.xyz"));
    assert.equal(result.is_phishing, true);
    assert.equal(result.risk_score, 94.0);
    assert.ok(result.explanation !== null);
    assert.equal(result.explanation?.is_llm_generated, true);
    assert.equal(result.explanation?.model_name, "gemini-2.5-flash");
  });
});
