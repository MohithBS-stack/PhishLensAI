"use client";

import React, { useEffect, useState, useRef } from "react";
import {
  fetchHealth,
  scanUnified,
  investigateMultimodal,
  HealthResponse,
  UnifiedReportResponse,
  UnifiedScanPayload,
  API_BASE_URL,
} from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { saveCaseApi } from "@/lib/cases";
import { Navbar } from "@/components/Navbar";
import { AuthModal, AuthMode } from "@/components/AuthModal";
import { InvestigationForm } from "@/components/InvestigationForm";
import { ReportDashboard } from "@/components/ReportDashboard";
import { SessionHistory } from "@/components/SessionHistory";
import {
  AlertTriangle,
  AlertOctagon,
  X,
  Shield,
  FileText,
  Globe,
  Image as ImageIcon,
  Mic,
  ArrowDown,
  Terminal,
  Cpu,
} from "lucide-react";

const SESSION_STORAGE_KEY = "phishlens_local_session_history";

export default function Home() {
  const { user, accessToken } = useAuth();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loadingHealth, setLoadingHealth] = useState<boolean>(true);
  const [currentReport, setCurrentReport] = useState<UnifiedReportResponse | null>(null);
  const [history, setHistory] = useState<UnifiedReportResponse[]>([]);
  const [loadingScan, setLoadingScan] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<AuthMode>("login");

  // Persistent database case saving states
  const [isSavedToDb, setIsSavedToDb] = useState<boolean>(false);
  const [isSavingToDb, setIsSavingToDb] = useState<boolean>(false);
  const [saveToDbError, setSaveToDbError] = useState<string | null>(null);
  const [casesRefreshTrigger, setCasesRefreshTrigger] = useState<number>(0);

  // User switch or logout isolation: flush active report when account changes
  const prevUserIdRef = useRef<string | null>(user?.id || null);
  useEffect(() => {
    if (prevUserIdRef.current && prevUserIdRef.current !== (user?.id || null)) {
      setCurrentReport(null);
      setIsSavedToDb(false);
      setSaveToDbError(null);
    }
    prevUserIdRef.current = user?.id || null;
  }, [user?.id]);

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

  const autoSaveCaseIfAuthenticated = async (report: UnifiedReportResponse, invType: string) => {
    if (!user || !accessToken) {
      setIsSavedToDb(false);
      setSaveToDbError(null);
      return;
    }
    setIsSavingToDb(true);
    setSaveToDbError(null);
    try {
      await saveCaseApi(
        {
          case_id: report.case_id,
          investigation_type: invType,
          report_payload: report,
        },
        accessToken
      );
      setIsSavedToDb(true);
      setCasesRefreshTrigger((prev) => prev + 1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to persist report to database";
      console.warn("[PhishLens] Auto-save case error:", msg);
      setSaveToDbError(msg);
      setIsSavedToDb(false);
    } finally {
      setIsSavingToDb(false);
    }
  };

  const handleManualSaveCase = async () => {
    if (!currentReport || !user || !accessToken || isSavedToDb || isSavingToDb) return;
    setIsSavingToDb(true);
    setSaveToDbError(null);
    try {
      await saveCaseApi(
        {
          case_id: currentReport.case_id,
          investigation_type: "unified",
          report_payload: currentReport,
        },
        accessToken
      );
      setIsSavedToDb(true);
      setCasesRefreshTrigger((prev) => prev + 1);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save dossier to database";
      setSaveToDbError(msg);
      setIsSavedToDb(false);
    } finally {
      setIsSavingToDb(false);
    }
  };

  // Run JSON investigation
  const handleScanJson = async (payload: UnifiedScanPayload) => {
    setLoadingScan(true);
    setScanError(null);
    setIsSavedToDb(false);
    setSaveToDbError(null);
    try {
      const report = await scanUnified(payload);
      setCurrentReport(report);
      saveToHistory(report);
      if (!health) checkHealth(0);
      await autoSaveCaseIfAuthenticated(report, "unified");
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
    setIsSavedToDb(false);
    setSaveToDbError(null);
    try {
      const report = await investigateMultimodal(formData);
      setCurrentReport(report);
      saveToHistory(report);
      if (!health) checkHealth(0);
      await autoSaveCaseIfAuthenticated(report, "multimodal");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Multimodal analysis failed";
      setScanError(msg);
    } finally {
      setLoadingScan(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#f6f5f0] text-[#121316] flex flex-col font-sans selection:bg-[#ea4e1b] selection:text-[#ffffff]">
      {/* Application Navigation Header */}
      <Navbar
        health={health}
        loadingHealth={loadingHealth}
        onRefreshHealth={() => checkHealth(0)}
        onNewScan={currentReport ? () => setCurrentReport(null) : undefined}
        onOpenAuth={(mode) => {
          setAuthModalMode(mode || "login");
          setIsAuthModalOpen(true);
        }}
      />

      {/* Main Investigation Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8 space-y-8">
        {/* Editorial Swiss/Bauhaus Hero & System Overview */}
        <section className="bg-[#ffffff] border border-[#cfccc2] p-6 sm:p-8 shadow-sm">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-[#e4e1d8]">
            <div className="space-y-2 max-w-3xl">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-mono tracking-widest text-[#ea4e1b] uppercase font-bold bg-[#fdf3ef] px-2 py-0.5 border border-[#f8ab93]">
                  OPERATIONAL SPECIFICATION v1.0
                </span>
                <span className="text-[10px] font-mono tracking-wider text-[#747782] uppercase">
                  CYBERSECURITY FORENSIC ENGINE
                </span>
                {user && (
                  <span className="text-[10px] font-mono tracking-wider text-[#185a30] uppercase font-bold bg-[#e8f6ed] px-2 py-0.5 border border-[#a8dfba] flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#1b7e41]" />
                    <span>OPERATOR: {user.email}</span>
                  </span>
                )}
              </div>
              <h1 className="text-2xl sm:text-4xl font-mono font-extrabold tracking-tight text-[#121316]">
                Multimodal Threat Investigation &amp; Evidence Fusion
              </h1>
              <p className="text-xs sm:text-sm text-[#4d5058] leading-relaxed font-sans">
                PhishLens AI executes passive, evidence-grounded threat triage across message transcripts, embedded URLs, screenshot OCR captures, and voicemail audio. Features are correlated through dual ML classifiers and psychological manipulation detection into an explainable forensic dossier.
              </p>
            </div>

            {/* Quick Modality Capability Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono shrink-0">
              <div className="p-2.5 border border-[#e4e1d8] bg-[#faf9f5]">
                <div className="flex items-center gap-1.5 text-[10px] text-[#747782] uppercase mb-0.5">
                  <FileText className="w-3 h-3 text-[#ea4e1b]" />
                  <span>MODEL A</span>
                </div>
                <div className="font-bold text-[#121316] text-[11px]">SMS Smishing NLP</div>
              </div>
              <div className="p-2.5 border border-[#e4e1d8] bg-[#faf9f5]">
                <div className="flex items-center gap-1.5 text-[10px] text-[#747782] uppercase mb-0.5">
                  <Globe className="w-3 h-3 text-[#ea4e1b]" />
                  <span>MODEL B</span>
                </div>
                <div className="font-bold text-[#121316] text-[11px]">PhiUSIIL URL Engine</div>
              </div>
              <div className="p-2.5 border border-[#e4e1d8] bg-[#faf9f5]">
                <div className="flex items-center gap-1.5 text-[10px] text-[#747782] uppercase mb-0.5">
                  <ImageIcon className="w-3 h-3 text-[#ea4e1b]" />
                  <span>VISION</span>
                </div>
                <div className="font-bold text-[#121316] text-[11px]">OCR Extraction</div>
              </div>
              <div className="p-2.5 border border-[#e4e1d8] bg-[#faf9f5]">
                <div className="flex items-center gap-1.5 text-[10px] text-[#747782] uppercase mb-0.5">
                  <Mic className="w-3 h-3 text-[#ea4e1b]" />
                  <span>SPEECH</span>
                </div>
                <div className="font-bold text-[#121316] text-[11px]">Whisper STT Core</div>
              </div>
            </div>
          </div>

          {/* Workflow Sequence Indicator */}
          <div className="pt-4 flex flex-col sm:flex-row sm:items-center justify-between text-[11px] font-mono text-[#747782] gap-2">
            <div className="flex items-center gap-2">
              <span className="font-bold text-[#121316]">WORKFLOW:</span>
              <span>1. Ingest Evidence</span>
              <span>›</span>
              <span>2. Passive Feature Extraction</span>
              <span>›</span>
              <span>3. Classifier Inference</span>
              <span>›</span>
              <span>4. Structured Dossier</span>
            </div>
            <div className="text-[10px] uppercase font-bold text-[#ea4e1b]">
              ZERO HOST VISITS • PASSIVE ONLY
            </div>
          </div>
        </section>

        {/* Backend Warning Banner if offline */}
        {!loadingHealth && !health && (
          <div className="p-4 bg-[#fef8ee] border border-[#fcd38d] text-xs font-mono text-[#b45309] flex items-start gap-3 shadow-sm">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#b45309] mt-0.5" />
            <div className="space-y-1">
              <p className="font-bold uppercase tracking-wider">
                BACKEND SERVICE UNREACHABLE
              </p>
              <p className="text-[#4d5058] font-sans text-xs">
                The frontend cannot currently establish a connection with the FastAPI backend at{" "}
                <code className="text-[#b45309] font-mono font-bold bg-[#ffffff] px-1.5 py-0.5 border border-[#fcd38d]">
                  {API_BASE_URL}
                </code>
                . Please verify that the backend process is running or click the API status button in the top navigation bar to retry.
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
          <div className="p-4 bg-[#fdf3ef] border border-[#f8ab93] text-xs font-mono text-[#ea4e1b] flex items-start justify-between gap-3 shadow-sm">
            <div className="flex items-start gap-2.5">
              <AlertOctagon className="w-4 h-4 text-[#ea4e1b] shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block uppercase tracking-wider">
                  INVESTIGATION DISPATCH ERROR
                </span>
                <p className="text-[#4d5058] font-sans text-xs mt-0.5">{scanError}</p>
              </div>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-[#747782] hover:text-[#ea4e1b] p-1 cursor-pointer"
              title="Dismiss error"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Results Report Dashboard */}
        {currentReport && (
          <div className="scroll-mt-20">
            <ReportDashboard
              report={currentReport}
              onReset={() => {
                setCurrentReport(null);
                setIsSavedToDb(false);
                setSaveToDbError(null);
              }}
              isSavedToDb={isSavedToDb}
              isSavingToDb={isSavingToDb}
              saveToDbError={saveToDbError}
              onSaveToDb={handleManualSaveCase}
              onOpenAuth={(mode) => {
                setAuthModalMode(mode || "login");
                setIsAuthModalOpen(true);
              }}
              isAuthenticated={Boolean(user && accessToken)}
            />
          </div>
        )}

        {/* Session History Ledger */}
        <SessionHistory
          history={history}
          onSelectCase={(caseItem) => {
            setCurrentReport(caseItem);
            setIsSavedToDb(Boolean(user && accessToken));
            setSaveToDbError(null);
            window.scrollTo({ top: 400, behavior: "smooth" });
          }}
          onClearHistory={handleClearHistory}
          currentCaseId={currentReport?.case_id}
          onOpenAuth={(mode) => {
            setAuthModalMode(mode || "login");
            setIsAuthModalOpen(true);
          }}
          refreshTrigger={casesRefreshTrigger}
        />
      </main>

      {/* Industrial Security Console Footer */}
      <footer className="border-t border-[#cfccc2] bg-[#ffffff] px-4 sm:px-6 lg:px-8 py-6 text-xs font-mono text-[#747782] mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-4 w-4 bg-[#ea4e1b] text-[#ffffff] flex items-center justify-center font-bold text-[9px]">
              PL
            </div>
            <span>PHISHLENS AI // FORENSIC TRIAGE CONSOLE</span>
            <span className="text-[#cfccc2]">|</span>
            <span>CYBERFORGE 2026</span>
          </div>

          <div className="text-[11px] text-center sm:text-right text-[#4d5058]">
            Passive threat evaluation protocol • Zero external domain crawling • No server-side payload retention
          </div>
        </div>
      </footer>

      {/* Operator Authentication & Registration Modal Dialog */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        initialMode={authModalMode}
      />
    </div>
  );
}
