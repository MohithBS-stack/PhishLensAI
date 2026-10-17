"use client";

import React from "react";
import { HealthResponse, API_BASE_URL } from "@/lib/api";
import { Shield, RefreshCw, Radio, Terminal } from "lucide-react";

interface NavbarProps {
  health: HealthResponse | null;
  loadingHealth: boolean;
  onRefreshHealth: () => void;
  onNewScan?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  health,
  loadingHealth,
  onRefreshHealth,
  onNewScan,
}) => {
  const isHealthy = health?.status === "healthy" || health?.status === "ok";

  return (
    <header className="sticky top-0 z-40 w-full bg-[#111215] text-[#f6f5f0] border-b border-[#27282f] shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        {/* Wordmark & Product Identifier */}
        <div className="flex items-center gap-3">
          <div className="h-7 w-7 bg-[#ea4e1b] flex items-center justify-center text-[#111215] font-mono font-bold text-xs tracking-tighter shrink-0">
            <Shield className="w-4 h-4 text-[#111215]" strokeWidth={2.5} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-mono font-extrabold text-sm sm:text-base tracking-tight text-[#f6f5f0]">
              PHISHLENS
            </span>
            <span className="font-mono text-[10px] tracking-widest text-[#ea4e1b] uppercase font-semibold">
              // FORENSIC CORE
            </span>
            <span className="hidden sm:inline-block text-[10px] font-mono tracking-wider text-[#747782] uppercase border-l border-[#27282f] pl-2">
              PASSIVE INVESTIGATION SYSTEM
            </span>
          </div>
        </div>

        {/* Operational Status & Direct Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Backend Connectivity Status Button */}
          <button
            onClick={onRefreshHealth}
            disabled={loadingHealth}
            title={
              loadingHealth
                ? `Pinging endpoint ${API_BASE_URL}...`
                : isHealthy
                ? `Backend online at ${API_BASE_URL}. Click to re-verify.`
                : `Backend unreachable at ${API_BASE_URL}. Click to retry.`
            }
            className={`inline-flex items-center gap-2 px-2.5 py-1 text-[11px] font-mono tracking-wider uppercase border transition-colors cursor-pointer ${
              loadingHealth
                ? "bg-[#18191d] text-[#9a9ca8] border-[#27282f]"
                : isHealthy
                ? "bg-[#14231b] text-[#9ed4b9] border-[#1d4731] hover:bg-[#1a3024]"
                : "bg-[#281615] text-[#f8ab93] border-[#5e2720] hover:bg-[#341d1a]"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                loadingHealth
                  ? "bg-[#fcd38d] animate-pulse"
                  : isHealthy
                  ? "bg-[#177846]"
                  : "bg-[#ea4e1b]"
              }`}
            />
            <span className="hidden md:inline">
              {loadingHealth
                ? "POLLING API..."
                : isHealthy
                ? "API ONLINE"
                : "API OFFLINE"}
            </span>
            <span className="md:hidden">
              {loadingHealth ? "POLL" : isHealthy ? "LIVE" : "DOWN"}
            </span>
            <RefreshCw
              className={`w-3 h-3 text-[#747782] ${
                loadingHealth ? "animate-spin" : ""
              }`}
            />
          </button>

          {/* Model Registry Status Badge */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono tracking-wider text-[#9a9ca8] bg-[#18191d] border border-[#27282f]">
            <Radio className="w-3 h-3 text-[#ea4e1b]" />
            <span>MODELS: 2 LOADED</span>
          </div>

          {/* New Investigation Action */}
          {onNewScan && (
            <button
              onClick={onNewScan}
              className="inline-flex items-center gap-1.5 px-3 py-1 text-[11px] font-mono tracking-wider uppercase bg-[#ea4e1b] text-[#111215] font-bold hover:bg-[#d54212] transition-colors cursor-pointer"
            >
              <Terminal className="w-3 h-3" />
              <span>NEW SCAN</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
