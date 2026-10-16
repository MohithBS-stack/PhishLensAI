"use client";

import React, { useState } from "react";
import { UnifiedReportResponse, NormalizedEvidence, ManipulationTactic } from "@/lib/api";
import { ThreatScoreGauge } from "./ThreatScoreGauge";

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
    a.download = `phishlens-report-${case_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-rose-950 text-rose-300 border-rose-800";
      case "high":
        return "bg-orange-950 text-orange-300 border-orange-800";
      case "medium":
        return "bg-amber-950 text-amber-300 border-amber-800";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <div className="space-y-6 transition-all">
      {/* 1. Header & Verdict Summary Card */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/70 backdrop-blur-xl p-6 sm:p-8 shadow-2xl">
        <div className="flex flex-col lg:flex-row items-center justify-between gap-6 pb-6 border-b border-slate-800/80">
          <div className="flex-1 space-y-2 text-center lg:text-left">
            <div className="flex flex-wrap items-center justify-center lg:justify-start gap-2">
              <span className="font-mono text-xs text-slate-400 bg-slate-950 px-2.5 py-1 rounded-md border border-slate-800">
                Case: {case_id}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {timestamp ? new Date(timestamp).toLocaleTimeString() : "Just now"}
              </span>
              {explanation.is_llm_generated ? (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                  AI Grounded Briefing ({explanation.model_name || "Gemini"})
                </span>
              ) : (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Deterministic Rule Briefing
                </span>
              )}
            </div>

            <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              {explanation.summary}
            </h2>

            <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
              {explanation.executive_brief}
            </p>
          </div>

          {/* Circular Threat Gauge */}
          <div className="flex-shrink-0">
            <ThreatScoreGauge score={score} verdict={verdict} size={170} />
          </div>
        </div>

        {/* Action Controls & Calibration Disclaimer */}
        <div className="pt-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
          <div className="text-slate-500 italic max-w-lg text-center sm:text-left">
            Notice: {uncertainty.calibration_disclosure}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyMarkdown}
              className="px-3 py-1.5 rounded-lg font-medium text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              {copiedMarkdown ? (
                <>
                  <span className="text-emerald-400 font-bold">✓</span>
                  <span>Copied!</span>
                </>
              ) : (
                <span>Copy Summary (MD)</span>
              )}
            </button>
            <button
              onClick={handleDownloadJson}
              className="px-3 py-1.5 rounded-lg font-medium text-xs bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800 transition-colors cursor-pointer"
            >
              Export JSON Report
            </button>
            {onReset && (
              <button
                onClick={onReset}
                className="px-3 py-1.5 rounded-lg font-medium text-xs bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-colors cursor-pointer"
              >
                New Scan
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 2. Manipulation Tactics Section */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-6 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <span>Evidence-Backed Manipulation Tactics</span>
              <span className="text-xs px-2 py-0.5 rounded-full font-mono bg-slate-800 text-slate-300">
                {manipulation_tactics.length}
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Psychological coercion techniques observed in communication patterns
            </p>
          </div>
        </div>

        {manipulation_tactics.length === 0 ? (
          <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 text-center">
            No active urgency, artificial deadlines, secrecy demands, or impersonation tactics detected.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {manipulation_tactics.map((tactic) => (
              <div
                key={tactic.tactic_id}
                className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/50 space-y-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider font-mono text-cyan-400">
                    {tactic.category.replace("_", " ")}
                  </span>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border ${getSeverityBadgeClass(
                      tactic.severity
                    )}`}
                  >
                    {tactic.severity}
                  </span>
                </div>

                <h4 className="text-sm font-semibold text-white">{tactic.name}</h4>
                <p className="text-xs text-slate-400">{tactic.description}</p>

                {tactic.supporting_evidence && (
                  <div className="mt-2 p-2 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono text-amber-300">
                    <span className="text-slate-500 mr-2">Evidence Excerpt:</span>
                    &ldquo;{tactic.supporting_evidence}&rdquo;
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="mt-3 text-[11px] text-slate-500 italic">
          Disclaimer: Manipulation indicators reflect psychological tactics and are not definitive proof of malicious intent by themselves.
        </div>
      </div>

      {/* 3. Forensic Evidence by Modality */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
          <div>
            <h3 className="text-base font-bold text-white">
              Forensic Evidence Register
            </h3>
            <p className="text-xs text-slate-400">
              Normalized forensic signals categorized by originating modality
            </p>
          </div>

          {/* Modality Filter Pills */}
          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={() => setActiveModality("all")}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                activeModality === "all"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              All Signals ({all_evidence.length})
            </button>
            {availableModalities.map((mod) => (
              <button
                key={mod}
                onClick={() => setActiveModality(mod)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium capitalize transition-colors ${
                  activeModality === mod
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                    : "text-slate-400 hover:bg-slate-800"
                }`}
              >
                {mod} ({(evidence_by_modality[mod] || []).length})
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 space-y-3">
          {displayedEvidence.length === 0 ? (
            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 text-xs text-slate-400 text-center">
              No evidence recorded for the selected modality filter.
            </div>
          ) : (
            displayedEvidence.map((ev) => (
              <div
                key={ev.evidence_id}
                className="p-4 rounded-xl border border-slate-800/80 bg-slate-950/40 space-y-2 text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-slate-500 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                      {ev.evidence_id}
                    </span>
                    <span className="font-semibold text-slate-200 capitalize font-mono">
                      [{ev.source_modality}] {ev.indicator_type.replace("_", " ")}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                        ev.observed_versus_inferred === "observed"
                          ? "bg-blue-950/70 text-blue-300 border-blue-800"
                          : "bg-purple-950/70 text-purple-300 border-purple-800"
                      }`}
                    >
                      {ev.observed_versus_inferred}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getSeverityBadgeClass(
                        ev.severity
                      )}`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                </div>

                <p className="text-slate-300">{ev.description}</p>

                {ev.supporting_excerpt && (
                  <div className="p-2 rounded bg-slate-900/80 border border-slate-800 font-mono text-[11px] text-amber-200/90 break-all">
                    <span className="text-slate-500 mr-2 font-sans">Supporting Value:</span>
                    {ev.supporting_excerpt}
                  </div>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500 pt-1">
                  <span>Source: {ev.evidence_source}</span>
                  {ev.confidence !== null && (
                    <span>Confidence: {(ev.confidence * 100).toFixed(1)}%</span>
                  )}
                </div>

                {ev.limitations_and_missing_checks.length > 0 && (
                  <div className="pt-1.5 border-t border-slate-900 text-[11px] text-slate-500">
                    <span className="text-slate-400 font-semibold mr-1">Limitations:</span>
                    {ev.limitations_and_missing_checks.join("; ")}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* 4. Model Telemetry & Deterministic Scoring Breakdown */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-6 shadow-xl">
        <h3 className="text-base font-bold text-white mb-1">
          Technical Signals &amp; Deterministic Weight Allocation
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Exact scoring attribution across Model A (SMS), Model B (PhiUSIIL), and manipulation tactics
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          {/* Model A Box */}
          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1.5">
            <span className="text-cyan-400 font-bold block uppercase text-[11px]">
              Model A: SMS Spam Classifier
            </span>
            <div className="text-slate-300">
              Active: {model_signals.model_a_sms_classifier?.active ? "Yes" : "No"}
            </div>
            <div className="text-slate-300">
              Spam Probability:{" "}
              {model_signals.model_a_sms_classifier?.spam_probability !== null &&
              model_signals.model_a_sms_classifier?.spam_probability !== undefined
                ? `${(model_signals.model_a_sms_classifier.spam_probability * 100).toFixed(1)}%`
                : "N/A"}
            </div>
            <div className="text-slate-300 font-bold">
              Score Points:{" "}
              <span className="text-emerald-400">
                +{model_signals.model_a_sms_classifier?.points_contributed || 0} pts
              </span>{" "}
              (max 35)
            </div>
          </div>

          {/* Model B Box */}
          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1.5">
            <span className="text-cyan-400 font-bold block uppercase text-[11px]">
              Model B: PhiUSIIL URL Classifier
            </span>
            <div className="text-slate-300">
              Scanned URLs: {model_signals.model_b_url_classifier?.urls_scanned_count || 0}
            </div>
            <div className="text-slate-300">
              Phishing Flagged:{" "}
              {model_signals.model_b_url_classifier?.any_phishing ? (
                <span className="text-rose-400 font-bold">Yes</span>
              ) : (
                "No"
              )}
            </div>
            <div className="text-slate-300 font-bold">
              Score Points:{" "}
              <span className="text-emerald-400">
                +{model_signals.model_b_url_classifier?.points_contributed || 0} pts
              </span>{" "}
              (max 45)
            </div>
          </div>

          {/* Heuristics & Dampening Box */}
          <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/80 space-y-1.5">
            <span className="text-cyan-400 font-bold block uppercase text-[11px]">
              Heuristics &amp; Correlation Dampening
            </span>
            <div className="text-slate-300">
              Categories:{" "}
              {model_signals.heuristics_and_tactics?.categories_detected?.join(", ") || "None"}
            </div>
            <div className="text-slate-300">
              Correlation Discount:{" "}
              <span className="text-amber-400">
                -{model_signals.heuristics_and_tactics?.correlation_dampening_applied || 0} pts
              </span>
            </div>
            <div className="text-slate-300 font-bold">
              Capped Tactic Points:{" "}
              <span className="text-emerald-400">
                +{model_signals.heuristics_and_tactics?.capped_tactic_points || 0} pts
              </span>{" "}
              (max 35)
            </div>
          </div>
        </div>
      </div>

      {/* 5. Uncertainty & Missing Checks */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Missing Checks */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-5 shadow-xl space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Explicitly Omitted Verifications
          </h4>
          <p className="text-[11px] text-slate-500">
            For safety and privacy, PhishLens AI strictly adheres to passive evaluation
          </p>
          <ul className="space-y-1.5 pt-2 text-xs text-slate-400 list-disc list-inside">
            {missing_checks.map((chk, i) => (
              <li key={i}>{chk}</li>
            ))}
          </ul>
        </div>

        {/* Safe Next Steps */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-5 shadow-xl space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400">
            Prescriptive Action Playbook
          </h4>
          <p className="text-[11px] text-slate-500">
            Recommended response procedures for employees and security analysts
          </p>
          <ul className="space-y-2 pt-2 text-xs text-slate-200">
            {safe_next_steps.map((step, idx) => (
              <li key={idx} className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
