"use client";

import React from "react";
import { UnifiedReportResponse } from "@/lib/api";

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

  const getVerdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case "high-risk":
        return "text-rose-400 border-rose-800 bg-rose-950/60";
      case "suspicious":
        return "text-amber-400 border-amber-800 bg-amber-950/60";
      case "benign":
        return "text-emerald-400 border-emerald-800 bg-emerald-950/60";
      default:
        return "text-slate-400 border-slate-700 bg-slate-900";
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-5 shadow-xl transition-all space-y-3">
      <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span>Local Session History</span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
              {history.length}
            </span>
          </h3>
          <p className="text-[11px] text-slate-400 italic mt-0.5">
            Stored in local browser session only (not persisted on server)
          </p>
        </div>

        <button
          onClick={onClearHistory}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
        >
          Clear History
        </button>
      </div>

      <div className="flex flex-col gap-2 max-h-56 overflow-y-auto pr-1">
        {history.map((item) => {
          const isSelected = item.case_id === currentCaseId;
          return (
            <button
              key={item.case_id}
              onClick={() => onSelectCase(item)}
              className={`w-full text-left p-3 rounded-xl border text-xs transition-all flex items-center justify-between cursor-pointer ${
                isSelected
                  ? "bg-slate-800/90 border-cyan-500/70 shadow-md shadow-cyan-500/10"
                  : "bg-slate-950/40 border-slate-800/80 hover:bg-slate-900/80 hover:border-slate-700"
              }`}
            >
              <div className="space-y-1 overflow-hidden pr-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-semibold text-slate-300">
                    {item.case_id}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : ""}
                  </span>
                </div>
                <p className="text-slate-400 truncate max-w-sm text-[11px]">
                  {item.explanation.summary}
                </p>
              </div>

              <div className="flex items-center gap-2 flex-shrink-0">
                <span className="font-mono font-bold text-slate-200">
                  {item.verdict === "inconclusive" ? "—" : `${item.score.toFixed(1)}/100`}
                </span>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] uppercase font-bold border ${getVerdictColor(
                    item.verdict
                  )}`}
                >
                  {item.verdict}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};
