"use client";

import React, { useState } from "react";
import {
  UnifiedReportResponse,
  NormalizedEvidence,
  ManipulationTactic,
} from "@/lib/api";
import { ThreatScoreGauge } from "./ThreatScoreGauge";
import {
  FileText,
  Copy,
  Download,
  RotateCcw,
  Check,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ExternalLink,
  Layers,
  Cpu,
  Terminal,
  FileSpreadsheet,
  Info,
} from "lucide-react";

interface ReportDashboardProps {
  report: UnifiedReportResponse;
  onReset?: () => void;
}

export const ReportDashboard: React.FC<ReportDashboardProps> = ({
  report,
  onReset,
}) => {
  const [activeModality, setActiveModality] = useState<string>("all");
  const [copiedMarkdown, setCopiedMarkdown] = useState(false);

  const {
    case_id,
    verdict,
    score,
    evidence_by_modality,
    all_evidence,
    manipulation_tactics,
    supporting_excerpts,
    model_signals,
    missing_checks,
    uncertainty,
    safe_next_steps,
    explanation,
    timestamp,
  } = report;

  // Filter evidence based on selected modality tab
  const displayedEvidence =
    activeModality === "all"
      ? all_evidence
      : evidence_by_modality[activeModality] || [];

  const availableModalities = Object.keys(evidence_by_modality).filter(
    (k) => (evidence_by_modality[k] || []).length > 0
  );

  // Copy Markdown Report to Clipboard
  const handleCopyMarkdown = () => {
    const md = `
# PhishLens AI Forensic Threat Report
**Case ID:** ${case_id}  
**Verdict:** ${verdict.toUpperCase()}  
**Composite Threat Score:** ${score}/100  
**Timestamp:** ${timestamp || new Date().toISOString()}  

## Executive Summary
${explanation.executive_brief}

## Key Identified Concerns
${explanation.key_concerns.map((c) => `- ${c}`).join("\n")}

## Manipulation & Social Engineering Tactics
${
  manipulation_tactics.length > 0
    ? manipulation_tactics
        .map(
          (t) =>
            `- **[${t.category.toUpperCase()}] ${t.name}** (${t.severity}): "${t.supporting_evidence}"`
        )
        .join("\n")
    : "No acute manipulation tactics detected."
}

## Safe Next Steps
${safe_next_steps.map((s) => `1. ${s}`).join("\n")}

## Disclaimers & Calibration Notice
${uncertainty.calibration_disclosure}
`.trim();

    navigator.clipboard.writeText(md).then(() => {
      setCopiedMarkdown(true);
      setTimeout(() => setCopiedMarkdown(false), 2500);
    });
  };

  // Export JSON Report Download
  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishlens-forensic-report-${case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-[#fdf3ef] text-[#ea4e1b] border-[#f8ab93]";
      case "high":
        return "bg-[#fdf3ef] text-[#ea4e1b] border-[#f8ab93]";
      case "medium":
        return "bg-[#fef8ee] text-[#b45309] border-[#fcd38d]";
      default:
        return "bg-[#f1f3f5] text-[#525763] border-[#c4c8d3]";
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Primary Investigation Dossier Header */}
      <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
        {/* Dossier Bar */}
        <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono tracking-widest text-[#ea4e1b] uppercase font-bold">
              [CASE DOSSIER]
            </span>
            <span className="text-xs font-mono font-bold text-[#121316]">
              {case_id}
            </span>
            <span className="text-[10px] font-mono text-[#747782] hidden sm:inline">
              // LOGGED: {timestamp ? new Date(timestamp).toLocaleTimeString() : "Just now"}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {explanation.is_llm_generated ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#f6f5f0] text-[#121316] border border-[#cfccc2]">
                <Cpu className="w-3 h-3 text-[#ea4e1b]" />
                <span>AI Grounded ({explanation.model_name || "Gemini"})</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono uppercase bg-[#f6f5f0] text-[#4d5058] border border-[#cfccc2]">
                <Terminal className="w-3 h-3" />
                <span>Deterministic Rule Briefing</span>
              </span>
            )}
          </div>
        </div>

        {/* Executive Headline & Threat Index Grid */}
        <div className="p-5 sm:p-6 flex flex-col lg:flex-row items-start justify-between gap-6">
          <div className="flex-1 space-y-3">
            <div className="text-[10px] font-mono tracking-widest text-[#747782] uppercase">
              EXECUTIVE BRIEFING &amp; CLASSIFICATION
            </div>
            <h2 className="text-xl sm:text-2xl font-mono font-bold tracking-tight text-[#121316]">
              {explanation.summary}
            </h2>
            <p className="text-xs sm:text-sm text-[#4d5058] leading-relaxed max-w-3xl font-sans">
              {explanation.executive_brief}
            </p>

            {/* Key Concerns Bullet Summary */}
            {explanation.key_concerns.length > 0 && (
              <div className="pt-2">
                <span className="text-[10px] font-mono tracking-wider text-[#747782] uppercase block mb-1">
                  IDENTIFIED THREAT INDICATORS:
                </span>
                <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs font-mono text-[#121316]">
                  {explanation.key_concerns.map((concern, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 bg-[#faf9f5] border border-[#e4e1d8] p-2">
                      <span className="text-[#ea4e1b] font-bold">›</span>
                      <span>{concern}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Architectural Threat Score Index */}
          <div className="w-full lg:w-auto shrink-0 flex justify-center">
            <ThreatScoreGauge score={score} verdict={verdict} />
          </div>
        </div>

        {/* Action Controls & Calibration Disclaimer Bar */}
        <div className="px-5 py-3 border-t border-[#e4e1d8] bg-[#faf9f5] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
          <div className="text-[11px] text-[#747782] leading-snug">
            <strong className="text-[#4d5058]">CALIBRATION:</strong> {uncertainty.calibration_disclosure}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleCopyMarkdown}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#ffffff] hover:bg-[#edebe4] text-[#121316] border border-[#cfccc2] transition-colors cursor-pointer text-xs uppercase"
            >
              {copiedMarkdown ? (
                <>
                  <Check className="w-3.5 h-3.5 text-[#177846]" />
                  <span>COPIED (MD)</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-[#747782]" />
                  <span>COPY (MD)</span>
                </>
              )}
            </button>
            <button
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#ffffff] hover:bg-[#edebe4] text-[#121316] border border-[#cfccc2] transition-colors cursor-pointer text-xs uppercase"
            >
              <Download className="w-3.5 h-3.5 text-[#747782]" />
              <span>EXPORT JSON</span>
            </button>
            {onReset && (
              <button
                onClick={onReset}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#ea4e1b] hover:bg-[#d54212] text-[#ffffff] border border-[#ea4e1b] transition-colors cursor-pointer text-xs uppercase font-bold"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>NEW SCAN</span>
              </button>
            )}
          </div>
        </div>
      </section>

      {/* 2. Manipulation Tactics Breakdown */}
      <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
        <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#ea4e1b]" />
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
              Psychological Manipulation &amp; Social Engineering Tactics
            </span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#f6f5f0] border border-[#cfccc2] text-[#4d5058] font-bold">
            {manipulation_tactics.length} DETECTED
          </span>
        </div>

        <div className="p-5">
          {manipulation_tactics.length === 0 ? (
            <div className="p-4 bg-[#eff8f3] border border-[#9ed4b9] text-xs font-mono text-[#177846] flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>No active urgency, artificial deadlines, secrecy demands, or impersonation tactics detected.</span>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {manipulation_tactics.map((tactic) => (
                <div
                  key={tactic.tactic_id}
                  className="p-4 border border-[#cfccc2] bg-[#faf9f5] space-y-2 hover:border-[#ea4e1b] transition-colors"
                >
                  <div className="flex items-center justify-between pb-1 border-b border-[#e4e1d8]">
                    <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-[#ea4e1b]">
                      [{tactic.category.replace("_", " ")}]
                    </span>
                    <span
                      className={`text-[9px] uppercase font-mono font-bold px-2 py-0.5 border ${getSeverityBadgeClass(
                        tactic.severity
                      )}`}
                    >
                      SEVERITY: {tactic.severity}
                    </span>
                  </div>

                  <h4 className="text-xs font-mono font-bold text-[#121316]">
                    {tactic.name}
                  </h4>
                  <p className="text-xs text-[#4d5058] font-sans">
                    {tactic.description}
                  </p>

                  {tactic.supporting_evidence && (
                    <div className="mt-2 p-2 bg-[#ffffff] border border-[#cfccc2] text-xs font-mono text-[#121316]">
                      <span className="text-[#747782] mr-2 text-[10px] uppercase font-bold">EXCERPT:</span>
                      &ldquo;{tactic.supporting_evidence}&rdquo;
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          <p className="text-[10px] font-mono text-[#747782] uppercase mt-3">
            Passive heuristic evaluation • Indicators flag cognitive pressure patterns without accessing private records
          </p>
        </div>
      </section>

      {/* 3. Forensic Evidence Register */}
      <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
        <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="w-4 h-4 text-[#ea4e1b]" />
            <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
              Forensic Evidence Register
            </span>
          </div>

          {/* Modality Filter Pills */}
          <div className="flex flex-wrap gap-1 font-mono text-xs">
            <button
              onClick={() => setActiveModality("all")}
              className={`px-2.5 py-1 text-[11px] uppercase transition-colors cursor-pointer ${
                activeModality === "all"
                  ? "bg-[#111215] text-[#f6f5f0] border border-[#111215] font-bold"
                  : "bg-[#ffffff] text-[#4d5058] border border-[#cfccc2] hover:bg-[#edebe4]"
              }`}
            >
              All Signals ({all_evidence.length})
            </button>
            {availableModalities.map((mod) => (
              <button
                key={mod}
                onClick={() => setActiveModality(mod)}
                className={`px-2.5 py-1 text-[11px] uppercase transition-colors cursor-pointer ${
                  activeModality === mod
                    ? "bg-[#111215] text-[#f6f5f0] border border-[#111215] font-bold"
                    : "bg-[#ffffff] text-[#4d5058] border border-[#cfccc2] hover:bg-[#edebe4]"
                }`}
              >
                {mod} ({(evidence_by_modality[mod] || []).length})
              </button>
            ))}
          </div>
        </div>

        <div className="p-5 space-y-3">
          {displayedEvidence.length === 0 ? (
            <div className="p-4 bg-[#faf9f5] border border-[#cfccc2] text-xs font-mono text-[#747782] text-center">
              No evidence recorded for the active modality filter.
            </div>
          ) : (
            displayedEvidence.map((ev) => (
              <div
                key={ev.evidence_id}
                className="p-3.5 border border-[#cfccc2] bg-[#faf9f5] space-y-2 text-xs font-mono"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-[#e4e1d8]">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#747782] bg-[#ffffff] px-1.5 py-0.5 border border-[#cfccc2]">
                      {ev.evidence_id}
                    </span>
                    <span className="font-bold text-[#121316] uppercase">
                      [{ev.source_modality}] {ev.indicator_type.replace("_", " ")}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <span
                      className={`px-1.5 py-0.5 text-[9px] uppercase font-bold border ${
                        ev.observed_versus_inferred === "observed"
                          ? "bg-[#eff8f3] text-[#177846] border-[#9ed4b9]"
                          : "bg-[#f1f3f5] text-[#525763] border-[#c4c8d3]"
                      }`}
                    >
                      {ev.observed_versus_inferred}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 text-[9px] uppercase font-bold border ${getSeverityBadgeClass(
                        ev.severity
                      )}`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-[#121316] font-sans">
                  {ev.description}
                </p>

                {ev.supporting_excerpt && (
                  <div className="p-2 bg-[#ffffff] border border-[#cfccc2] text-[11px] text-[#ea4e1b] break-all">
                    <span className="text-[#747782] mr-2 text-[10px] uppercase font-bold font-mono">SUPPORTING EXCERPT:</span>
                    {ev.supporting_excerpt}
                  </div>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-[#747782] pt-1">
                  <span>SOURCE: {ev.evidence_source}</span>
                  {ev.confidence !== null && (
                    <span className="tabular-nums">CONFIDENCE: {(ev.confidence * 100).toFixed(1)}%</span>
                  )}
                </div>

                {ev.limitations_and_missing_checks.length > 0 && (
                  <div className="pt-1.5 border-t border-[#e4e1d8] text-[10px] text-[#747782]">
                    <span className="text-[#4d5058] font-semibold mr-1">LIMITATIONS:</span>
                    {ev.limitations_and_missing_checks.join("; ")}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </section>

      {/* 4. Technical Telemetry & Weight Allocation */}
      <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
        <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5]">
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
            Technical Telemetry &amp; Deterministic Scoring Attribution
          </span>
          <p className="text-[10px] font-mono text-[#747782]">
            Exact point contribution breakdown across Model A, Model B, and manipulation tactics
          </p>
        </div>

        <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          {/* Model A Box */}
          <div className="p-3.5 border border-[#cfccc2] bg-[#faf9f5] space-y-1">
            <span className="text-[10px] font-bold text-[#ea4e1b] uppercase block">
              MODEL A: SMS CLASSIFIER
            </span>
            <div className="text-[#4d5058]">
              ACTIVE: {model_signals.model_a_sms_classifier?.active ? "TRUE" : "FALSE"}
            </div>
            <div className="text-[#4d5058] tabular-nums">
              SPAM PROBABILITY:{" "}
              {model_signals.model_a_sms_classifier?.spam_probability !== null &&
              model_signals.model_a_sms_classifier?.spam_probability !== undefined
                ? `${(model_signals.model_a_sms_classifier.spam_probability * 100).toFixed(1)}%`
                : "N/A"}
            </div>
            <div className="text-[#121316] font-bold pt-1 border-t border-[#e4e1d8]">
              SCORE POINTS:{" "}
              <span className="text-[#177846] tabular-nums">
                +{model_signals.model_a_sms_classifier?.points_contributed || 0} PTS
              </span>{" "}
              (MAX 35)
            </div>
          </div>

          {/* Model B Box */}
          <div className="p-3.5 border border-[#cfccc2] bg-[#faf9f5] space-y-1">
            <span className="text-[10px] font-bold text-[#ea4e1b] uppercase block">
              MODEL B: PHIUSIIL URL CLASSIFIER
            </span>
            <div className="text-[#4d5058] tabular-nums">
              SCANNED URLS: {model_signals.model_b_url_classifier?.urls_scanned_count || 0}
            </div>
            <div className="text-[#4d5058]">
              PHISHING DETECTED:{" "}
              {model_signals.model_b_url_classifier?.any_phishing ? (
                <span className="text-[#ea4e1b] font-bold">YES</span>
              ) : (
                "NO"
              )}
            </div>
            <div className="text-[#121316] font-bold pt-1 border-t border-[#e4e1d8]">
              SCORE POINTS:{" "}
              <span className="text-[#177846] tabular-nums">
                +{model_signals.model_b_url_classifier?.points_contributed || 0} PTS
              </span>{" "}
              (MAX 45)
            </div>
          </div>

          {/* Heuristics & Dampening Box */}
          <div className="p-3.5 border border-[#cfccc2] bg-[#faf9f5] space-y-1">
            <span className="text-[10px] font-bold text-[#ea4e1b] uppercase block">
              TACTICS &amp; CORRELATION DAMPENING
            </span>
            <div className="text-[#4d5058] truncate">
              CATEGORIES:{" "}
              {model_signals.heuristics_and_tactics?.categories_detected?.join(", ") || "NONE"}
            </div>
            <div className="text-[#4d5058] tabular-nums">
              CORRELATION DISCOUNT:{" "}
              <span className="text-[#b45309]">
                -{model_signals.heuristics_and_tactics?.correlation_dampening_applied || 0} PTS
              </span>
            </div>
            <div className="text-[#121316] font-bold pt-1 border-t border-[#e4e1d8]">
              CAPPED POINTS:{" "}
              <span className="text-[#177846] tabular-nums">
                +{model_signals.heuristics_and_tactics?.capped_tactic_points || 0} PTS
              </span>{" "}
              (MAX 35)
            </div>
          </div>
        </div>
      </section>

      {/* 5. Uncertainty & Operational Playbook Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Missing Checks & Passive Evaluation Limits */}
        <section className="bg-[#ffffff] border border-[#cfccc2] p-5 shadow-sm space-y-2">
          <div className="flex items-center gap-1.5 pb-2 border-b border-[#e4e1d8]">
            <Info className="w-4 h-4 text-[#747782]" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
              Explicitly Omitted Verifications
            </h4>
          </div>
          <p className="text-[11px] font-mono text-[#747782]">
            Passive triage limits: no server visits or external queries
          </p>
          <ul className="space-y-1.5 pt-2 text-xs font-mono text-[#4d5058]">
            {missing_checks.map((chk, i) => (
              <li key={i} className="flex items-start gap-1.5">
                <span className="text-[#747782] font-bold">•</span>
                <span>{chk}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* Prescriptive Safe Next Actions */}
        <section className="bg-[#ffffff] border border-[#cfccc2] p-5 shadow-sm space-y-2">
          <div className="flex items-center gap-1.5 pb-2 border-b border-[#e4e1d8]">
            <CheckCircle2 className="w-4 h-4 text-[#177846]" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[#177846]">
              Prescriptive Security Playbook
            </h4>
          </div>
          <p className="text-[11px] font-mono text-[#747782]">
            Standard incident response playbook recommendations
          </p>
          <ul className="space-y-2 pt-2 text-xs font-mono text-[#121316]">
            {safe_next_steps.map((step, idx) => (
              <li key={idx} className="flex items-start gap-2 bg-[#eff8f3] border border-[#9ed4b9] p-2">
                <Check className="w-3.5 h-3.5 text-[#177846] shrink-0 mt-0.5" />
                <span className="font-medium">{step}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
};
