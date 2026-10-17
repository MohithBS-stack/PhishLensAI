"use client";

import React from "react";
import { AlertOctagon, AlertTriangle, CheckCircle2, HelpCircle } from "lucide-react";

interface ThreatScoreGaugeProps {
  score: number;
  verdict: "benign" | "suspicious" | "high-risk" | "inconclusive" | string;
  size?: number; // Kept for backwards compatibility
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({
  score,
  verdict,
}) => {
  const boundedScore = Math.max(0, Math.min(100, Math.round(score * 10) / 10));

  // Determine technical status configuration based on verdict
  let config = {
    color: "#177846", // muted green
    bgClass: "bg-[#eff8f3] text-[#177846] border-[#9ed4b9]",
    badgeClass: "bg-[#177846] text-[#ffffff]",
    borderClass: "border-[#9ed4b9]",
    label: "VERIFIED BENIGN",
    icon: CheckCircle2,
    thresholdNote: "Score below 30.0 baseline",
  };

  if (verdict === "high-risk") {
    config = {
      color: "#ea4e1b", // signal orange
      bgClass: "bg-[#fdf3ef] text-[#ea4e1b] border-[#f8ab93]",
      badgeClass: "bg-[#ea4e1b] text-[#ffffff]",
      borderClass: "border-[#f8ab93]",
      label: "HIGH THREAT VECTOR",
      icon: AlertOctagon,
      thresholdNote: "Exceeds 70.0 high-risk threshold",
    };
  } else if (verdict === "suspicious") {
    config = {
      color: "#b45309", // industrial amber
      bgClass: "bg-[#fef8ee] text-[#b45309] border-[#fcd38d]",
      badgeClass: "bg-[#b45309] text-[#ffffff]",
      borderClass: "border-[#fcd38d]",
      label: "SUSPICIOUS VECTOR",
      icon: AlertTriangle,
      thresholdNote: "Crosses 30.0 suspicion threshold",
    };
  } else if (verdict === "inconclusive") {
    config = {
      color: "#525763", // neutral slate
      bgClass: "bg-[#f1f3f5] text-[#525763] border-[#c4c8d3]",
      badgeClass: "bg-[#525763] text-[#ffffff]",
      borderClass: "border-[#c4c8d3]",
      label: "INCONCLUSIVE",
      icon: HelpCircle,
      thresholdNote: "Insufficient evidence signals",
    };
  }

  const StatusIcon = config.icon;

  return (
    <div className="w-full sm:w-72 bg-[#ffffff] border border-[#cfccc2] p-4 flex flex-col justify-between shadow-sm">
      {/* Top Header Label */}
      <div className="flex items-center justify-between pb-2 border-b border-[#e4e1d8]">
        <span className="text-[10px] font-mono tracking-widest text-[#747782] uppercase font-semibold">
          COMPOSITE RISK INDEX
        </span>
        <div className="flex items-center gap-1">
          <StatusIcon className="w-3.5 h-3.5" style={{ color: config.color }} />
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider" style={{ color: config.color }}>
            {verdict}
          </span>
        </div>
      </div>

      {/* Numerical Display & Scale */}
      <div className="py-4">
        <div className="flex items-baseline justify-between">
          <span className="text-4xl sm:text-5xl font-mono font-extrabold tracking-tight tabular-nums text-[#121316]">
            {verdict === "inconclusive" ? "—" : boundedScore.toFixed(1)}
          </span>
          <div className="text-right">
            <span className="text-xs font-mono text-[#747782]">/ 100.0</span>
            <span className="block text-[10px] font-mono uppercase tracking-wider text-[#4d5058]">
              DETERMINISTIC
            </span>
          </div>
        </div>

        {/* Industrial Segmented Bar Scale */}
        <div className="mt-3 relative">
          {/* Background Track with tick marks */}
          <div className="h-2 w-full bg-[#edebe4] relative overflow-hidden flex">
            {/* Active progress fill */}
            <div
              className="h-full transition-all duration-700 ease-out"
              style={{
                width: `${verdict === "inconclusive" ? 0 : boundedScore}%`,
                backgroundColor: config.color,
              }}
            />
          </div>

          {/* Threshold Indicators: 0, 30 (Suspicious), 70 (High Risk), 100 */}
          <div className="flex justify-between items-center text-[9px] font-mono text-[#747782] mt-1.5 tabular-nums">
            <span>0</span>
            <span className="relative">
              <span className="text-[#b45309]">| 30</span>
              <span className="hidden sm:inline text-[8px] text-[#747782] ml-0.5">SUSP</span>
            </span>
            <span className="relative">
              <span className="text-[#ea4e1b]">| 70</span>
              <span className="hidden sm:inline text-[8px] text-[#747782] ml-0.5">HIGH</span>
            </span>
            <span>100</span>
          </div>
        </div>
      </div>

      {/* Footer Calibration Disclaimer */}
      <div className="pt-2 border-t border-[#e4e1d8] flex items-center justify-between text-[10px] font-mono text-[#747782]">
        <span className="uppercase tracking-wider">{config.thresholdNote}</span>
        <span className="uppercase text-[#4d5058] font-semibold">NOT PROBABILITY</span>
      </div>
    </div>
  );
};
