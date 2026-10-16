"use client";

import React, { useEffect, useState } from "react";
import {
  fetchHealth,
  scanUnified,
  investigateMultimodal,
  HealthResponse,
  UnifiedReportResponse,
  UnifiedScanPayload,
  API_BASE_URL,
} from "@/lib/api";
import { Navbar } from "@/components/Navbar";
import { InvestigationForm } from "@/components/InvestigationForm";
import { ReportDashboard } from "@/components/ReportDashboard";
import { SessionHistory } from "@/components/SessionHistory";

const SESSION_STORAGE_KEY = "phishlens_local_session_history";

export default function Home() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);
  const [currentReport, setCurrentReport] = useState<UnifiedReportResponse | null>(null);
  const [history, setHistory] = useState<UnifiedReportResponse[]>([]);
  const [loadingScan, setLoadingScan] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Manual health check trigger with overlap protection
  const checkHealth = (retriesLeft = 0, delayMs = 3000) => {
    if (loadingHealth && retriesLeft === 0) return; // Prevent duplicate overlapping clicks
    setLoadingHealth(true);
    fetchHealth()
      .then((data) => {
        setHealth(data);
        setLoadingHealth(false);
      })
      .catch((err) => {
        console.warn("[PhishLens] Health check attempt failed:", err);
        if (retriesLeft > 0) {
          setTimeout(() => {
            checkHealth(retriesLeft - 1, delayMs * 1.5);
          }, delayMs);
        } else {
          setHealth(null);
          setLoadingHealth(false);
        }
      });
  };

  useEffect(() => {
    let isMounted = true;
    let timerId: ReturnType<typeof setTimeout> | null = null;

    setLoadingHealth(true);
    const runInitialCheck = (retriesLeft: number, delay: number) => {
      fetchHealth()
        .then((data) => {
          if (!isMounted) return;
          setHealth(data);
          setLoadingHealth(false);
        })
        .catch((err) => {
          if (!isMounted) return;
          console.warn("[PhishLens] Initial health check failed:", err);
          if (retriesLeft > 0) {
            timerId = setTimeout(() => {
              if (isMounted) runInitialCheck(retriesLeft - 1, delay * 1.5);
            }, delay);
          } else {
            setHealth(null);
            setLoadingHealth(false);
          }
        });
    };

    runInitialCheck(2, 4000);

    // Load local browser session history
    try {
      const stored = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (stored) {
        const parsed: UnifiedReportResponse[] = JSON.parse(stored);
        setHistory(parsed);
      }
    } catch {
      // sessionStorage unavailable or parse error; fallback gracefully
    }

    return () => {
      isMounted = false;
      if (timerId) clearTimeout(timerId);
    };
  }, []);

  const saveToHistory = (newReport: UnifiedReportResponse) => {
    setHistory((prev) => {
      // Prepend and limit history to 15 items
      const updated = [newReport, ...prev.filter((c) => c.case_id !== newReport.case_id)].slice(0, 15);
      try {
        sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // storage quota exceeded or disabled
      }
      return updated;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {
      // ignore
    }
  };

  // Run JSON investigation
  const handleScanJson = async (payload: UnifiedScanPayload) => {
    setLoadingScan(true);
    setScanError(null);
    try {
      const report = await scanUnified(payload);
      setCurrentReport(report);
      saveToHistory(report);
      if (!health) checkHealth(0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Investigation failed";
      setScanError(msg);
    } finally {
      setLoadingScan(false);
    }
  };

  // Run Multimodal investigation (FormData)
  const handleScanMultimodal = async (formData: FormData) => {
    setLoadingScan(true);
    setScanError(null);
    try {
      const report = await investigateMultimodal(formData);
      setCurrentReport(report);
      saveToHistory(report);
      if (!health) checkHealth(0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Multimodal analysis failed";
      setScanError(msg);
    } finally {
      setLoadingScan(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Navigation Header */}
      <Navbar
        health={health}
        loadingHealth={loadingHealth}
        onRefreshHealth={() => checkHealth(0)}
      />

      {/* Main Workspace */}
      <main className="flex-1 max-w-6xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Hero Section */}
        <div className="space-y-2.5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
            <span className="h-1.5 w-10 rounded-full bg-cyan-400 animate-pulse" />
            CyberForge 2026 Production Triage
          </div>
          <h2 className="text-3xl sm:text-4xl font-black tracking-tight text-white">
            Multimodal Threat Investigation &amp; Evidence Fusion
          </h2>
          <p className="text-slate-400 text-sm sm:text-base max-w-3xl leading-relaxed">
            PhishLens AI fuses lexical URL analysis, SMS/smishing NLP models, screenshot OCR, and audio transcription into one unified forensic investigation backed by explainable psychological manipulation detection.
          </p>
        </div>

        {/* Backend Warning if offline */}
        {!loadingHealth && !health && (
          <div className="p-4 rounded-2xl bg-amber-950/40 border border-amber-800/80 text-xs text-amber-300 flex items-start gap-3">
            <span className="text-amber-400 font-bold text-sm">⚠️</span>
            <div>
              <p className="font-semibold mb-0.5">Backend Service Offline</p>
              <p className="text-slate-400">
                The frontend cannot currently connect to the FastAPI backend at{" "}
                <code className="text-amber-200">{API_BASE_URL}</code>. Please verify that the backend is running (`uvicorn app.main:app --port 8000`) or that CORS allows this origin.
              </p>
            </div>
          </div>
        )}

        {/* Investigation Input Form */}
        <InvestigationForm
          onSubmitJson={handleScanJson}
          onSubmitMultimodal={handleScanMultimodal}
          loading={loadingScan}
        />

        {/* Scan Error Banner */}
        {scanError && (
          <div className="p-4 rounded-2xl bg-rose-950/60 border border-rose-800/90 text-xs text-rose-300 flex items-start justify-between gap-3 shadow-lg">
            <div className="flex items-start gap-2.5">
              <span className="text-rose-400 font-bold text-base">✕</span>
              <div>
                <span className="font-bold block text-sm mb-0.5">
                  Investigation Error
                </span>
                <p className="text-slate-300">{scanError}</p>
              </div>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-slate-400 hover:text-slate-200 text-xs font-mono"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Results Report Dashboard */}
        {currentReport && (
          <ReportDashboard
            report={currentReport}
            onReset={() => setCurrentReport(null)}
          />
        )}

        {/* Session History Drawer */}
        <SessionHistory
          history={history}
          onSelectCase={(caseItem) => setCurrentReport(caseItem)}
          onClearHistory={handleClearHistory}
          currentCaseId={currentReport?.case_id}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 px-6 py-6 text-center text-xs text-slate-500 space-y-1">
        <p>PhishLens AI — Built for CyberForge Hackathon 2026.</p>
        <p className="text-[11px] text-slate-600">
          Strict passive evaluation only. Zero live domain crawling or server-side payload retention.
        </p>
      </footer>
    </div>
  );
}
