"use client";

import React from "react";

interface ThreatScoreGaugeProps {
  score: number;
  verdict: "benign" | "suspicious" | "high-risk" | "inconclusive" | string;
  size?: number;
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({
  score,
  verdict,
  size = 180,
}) => {
  const boundedScore = Math.max(0, Math.min(100, Math.round(score * 10) / 10));
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  // Arc spans 260 degrees
  const angleFraction = 260 / 360;
  const arcLength = circumference * angleFraction;
  const strokeDashoffset =
    arcLength - (boundedScore / 100) * arcLength;

  let colorClasses = {
    stroke: "#10b981", // emerald
    bgLight: "bg-emerald-950/40 text-emerald-300 border-emerald-800",
    textGlow: "text-emerald-400",
  };

  if (verdict === "high-risk") {
    colorClasses = {
      stroke: "#ef4444", // rose
      bgLight: "bg-rose-950/40 text-rose-300 border-rose-800",
      textGlow: "text-rose-400",
    };
  } else if (verdict === "suspicious") {
    colorClasses = {
      stroke: "#f59e0b", // amber
      bgLight: "bg-amber-950/40 text-amber-300 border-amber-800",
      textGlow: "text-amber-400",
    };
  } else if (verdict === "inconclusive") {
    colorClasses = {
      stroke: "#64748b", // slate
      bgLight: "bg-slate-900 text-slate-300 border-slate-700",
      textGlow: "text-slate-400",
    };
  }

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-220 overflow-visible"
        >
          {/* Background track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Active progress track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={colorClasses.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center score readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl sm:text-4xl font-extrabold font-mono tracking-tight text-white">
            {verdict === "inconclusive" ? "—" : boundedScore.toFixed(1)}
          </span>
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
            {verdict === "inconclusive" ? "No Score" : "Risk / 100"}
          </span>
        </div>
      </div>

      {/* Verdict Badge */}
      <div className="mt-2 text-center">
        <span
          className={`inline-block px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest border ${colorClasses.bgLight}`}
        >
          {verdict}
        </span>
      </div>
    </div>
  );
};
