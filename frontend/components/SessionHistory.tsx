"use client";

import React from "react";
import { UnifiedReportResponse } from "@/lib/api";
import { History, Trash2, ArrowRight, ShieldAlert, CheckCircle2, AlertTriangle, HelpCircle } from "lucide-react";

interface SessionHistoryProps {
  history: UnifiedReportResponse[];
  onSelectCase: (caseReport: UnifiedReportResponse) => void;
  onClearHistory: () => void;
  currentCaseId?: string;
}

export const SessionHistory: React.FC<SessionHistoryProps> = ({
  history,
  onSelectCase,
  onClearHistory,
  currentCaseId,
}) => {
  if (history.length === 0) {
    return null;
  }

  const getVerdictStyle = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case "high-risk":
        return {
          badge: "bg-[#fdf3ef] text-[#ea4e1b] border-[#f8ab93]",
          icon: ShieldAlert,
          iconColor: "text-[#ea4e1b]",
        };
      case "suspicious":
        return {
          badge: "bg-[#fef8ee] text-[#b45309] border-[#fcd38d]",
          icon: AlertTriangle,
          iconColor: "text-[#b45309]",
        };
      case "benign":
        return {
          badge: "bg-[#eff8f3] text-[#177846] border-[#9ed4b9]",
          icon: CheckCircle2,
          iconColor: "text-[#177846]",
        };
      default:
        return {
          badge: "bg-[#f1f3f5] text-[#525763] border-[#c4c8d3]",
          icon: HelpCircle,
          iconColor: "text-[#525763]",
        };
    }
  };

  return (
    <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
      {/* Header Bar */}
      <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-[#ea4e1b]" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
            Session Investigation Ledger
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#ffffff] border border-[#cfccc2] text-[#4d5058] font-bold">
            {history.length} CASES
          </span>
        </div>

        <button
          onClick={onClearHistory}
          className="inline-flex items-center gap-1 text-[11px] font-mono uppercase text-[#747782] hover:text-[#ea4e1b] transition-colors cursor-pointer"
        >
          <Trash2 className="w-3 h-3" />
          <span>PURGE SESSION</span>
        </button>
      </div>

      {/* Ledger Table / List */}
      <div className="divide-y divide-[#e4e1d8] max-h-72 overflow-y-auto">
        {history.map((item) => {
          const isSelected = item.case_id === currentCaseId;
          const { badge, icon: VerdictIcon, iconColor } = getVerdictStyle(item.verdict);

          return (
            <div
              key={item.case_id}
              onClick={() => onSelectCase(item)}
              className={`p-3.5 sm:px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono transition-colors cursor-pointer ${
                isSelected
                  ? "bg-[#faf9f5] border-l-4 border-l-[#ea4e1b]"
                  : "hover:bg-[#faf9f5] border-l-4 border-l-transparent"
              }`}
            >
              <div className="space-y-1 overflow-hidden pr-2 flex-1">
                <div className="flex items-center gap-2">
                  <VerdictIcon className={`w-3.5 h-3.5 ${iconColor} shrink-0`} />
                  <span className="font-bold text-[#121316]">
                    {item.case_id}
                  </span>
                  <span className="text-[10px] text-[#747782]">
                    {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ""}
                  </span>
                  {isSelected && (
                    <span className="text-[9px] font-mono uppercase font-bold text-[#ea4e1b] bg-[#fdf3ef] px-1.5 py-0.5 border border-[#f8ab93]">
                      ACTIVE
                    </span>
                  )}
                </div>
                <p className="text-[#4d5058] truncate max-w-xl text-[11px] font-sans">
                  {item.explanation.summary}
                </p>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <div className="text-right">
                  <span className="font-mono font-bold text-[#121316] tabular-nums">
                    {item.verdict === "inconclusive" ? "—" : `${item.score.toFixed(1)}/100`}
                  </span>
                </div>
                <span
                  className={`px-2 py-0.5 text-[9px] uppercase font-mono font-bold border ${badge}`}
                >
                  {item.verdict}
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-[#747782] hidden sm:inline" />
              </div>
            </div>
          );
        })}
      </div>

      <div className="px-5 py-2 border-t border-[#e4e1d8] bg-[#faf9f5] text-[10px] font-mono text-[#747782]">
        Ledger preserved in browser session storage only • Zero backend log retention
      </div>
    </section>
  );
};
