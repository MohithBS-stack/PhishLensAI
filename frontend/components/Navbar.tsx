"use client";

import React from "react";
import { HealthResponse } from "@/lib/api";

interface NavbarProps {
  health: HealthResponse | null;
  loadingHealth: boolean;
  onRefreshHealth: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  health,
  loadingHealth,
  onRefreshHealth,
}) => {
  const isHealthy = health?.status === "healthy";

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-4 sm:px-8 py-3.5 flex items-center justify-between transition-all">
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20">
          <div className="h-full w-full bg-slate-950 rounded-[10px] flex items-center justify-center font-black tracking-wider text-cyan-400 text-sm">
            PL
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold tracking-tight text-white">
              PhishLens AI
            </h1>
            <span className="text-[10px] uppercase font-mono tracking-widest px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-semibold">
              v1.0
            </span>
          </div>
          <p className="text-xs text-slate-400 hidden sm:block">
            Unified Evidence Fusion &amp; Explainable Threat Analysis
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          onClick={onRefreshHealth}
          title="Click to re-check backend connection"
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono font-medium border transition-colors cursor-pointer ${
            loadingHealth
              ? "bg-slate-900 text-slate-400 border-slate-700"
              : isHealthy
              ? "bg-emerald-950/70 text-emerald-300 border-emerald-800/80 hover:bg-emerald-900/60"
              : "bg-rose-950/70 text-rose-300 border-rose-800/80 hover:bg-rose-900/60"
          }`}
        >
          <span
            className={`h-2 w-2 rounded-full ${
              loadingHealth
                ? "bg-amber-400 animate-pulse"
                : isHealthy
                ? "bg-emerald-400 animate-pulse"
                : "bg-rose-400"
            }`}
          />
          <span className="hidden md:inline">
            {loadingHealth
              ? "Pinging API..."
              : isHealthy
              ? "Backend API Online"
              : "Backend Offline"}
          </span>
          <span className="md:hidden">
            {loadingHealth ? "Pinging" : isHealthy ? "Online" : "Offline"}
          </span>
        </button>

        <span className="hidden sm:inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono text-slate-400 bg-slate-900 border border-slate-800">
          CyberForge 2026
        </span>
      </div>
    </header>
  );
};
