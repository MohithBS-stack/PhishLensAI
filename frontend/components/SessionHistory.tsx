"use client";

import React, { useState, useEffect, useCallback } from "react";
import { UnifiedReportResponse } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import {
  listCasesApi,
  getCaseApi,
  deleteCaseApi,
  CaseSummary,
} from "@/lib/cases";
import {
  History,
  Trash2,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Database,
  Lock,
  LogIn,
  RefreshCw,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  AlertOctagon,
  X,
} from "lucide-react";

interface SessionHistoryProps {
  history: UnifiedReportResponse[];
  onSelectCase: (caseReport: UnifiedReportResponse) => void;
  onClearHistory: () => void;
  currentCaseId?: string;
  onOpenAuth?: (mode?: "login" | "register") => void;
  refreshTrigger?: number;
}

export const SessionHistory: React.FC<SessionHistoryProps> = ({
  history,
  onSelectCase,
  onClearHistory,
  currentCaseId,
  onOpenAuth,
  refreshTrigger = 0,
}) => {
  const { user, accessToken } = useAuth();

  // Persistent cases state (for authenticated users)
  const [persistentCases, setPersistentCases] = useState<CaseSummary[]>([]);
  const [totalCases, setTotalCases] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [loadingCases, setLoadingCases] = useState<boolean>(false);
  const [casesError, setCasesError] = useState<string | null>(null);

  // Interaction states
  const [deletingCaseId, setDeletingCaseId] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);
  const [loadingCaseDetailId, setLoadingCaseDetailId] = useState<string | null>(null);

  const fetchPersistentCases = useCallback(
    async (pageToFetch: number) => {
      if (!user || !accessToken) return;
      setLoadingCases(true);
      setCasesError(null);
      try {
        const data = await listCasesApi(pageToFetch, 10, accessToken);
        setPersistentCases(data.items);
        setTotalCases(data.total);
        setPage(data.page);
        setTotalPages(data.total_pages);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to load case ledger";
        setCasesError(msg);
      } finally {
        setLoadingCases(false);
      }
    },
    [user, accessToken]
  );

  useEffect(() => {
    if (user && accessToken) {
      fetchPersistentCases(page);
    } else {
      setPersistentCases([]);
      setTotalCases(0);
      setPage(1);
      setTotalPages(1);
      setCasesError(null);
    }
  }, [user, accessToken, page, refreshTrigger, fetchPersistentCases]);

  const handleSelectPersistentCase = async (item: CaseSummary) => {
    if (!accessToken) return;
    setLoadingCaseDetailId(item.case_id);
    setCasesError(null);
    try {
      const detail = await getCaseApi(item.case_id, accessToken);
      onSelectCase(detail.report_payload);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to retrieve case details";
      setCasesError(msg);
    } finally {
      setLoadingCaseDetailId(null);
    }
  };

  const handleDeletePersistentCase = async (caseId: string) => {
    if (!accessToken) return;
    setIsDeleting(true);
    setCasesError(null);
    try {
      await deleteCaseApi(caseId, accessToken);
      setDeletingCaseId(null);
      // If we just deleted the last item on a page > 1, go to previous page
      const nextPage = persistentCases.length === 1 && page > 1 ? page - 1 : page;
      setPage(nextPage);
      await fetchPersistentCases(nextPage);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete case";
      setCasesError(msg);
    } finally {
      setIsDeleting(false);
    }
  };

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

  // If user is logged out and has no local session history, we still show the prompt
  const isUserAuthenticated = Boolean(user && accessToken);

  return (
    <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
      {/* 1. Header Bar */}
      <div className="px-5 py-3 border-b border-[#e4e1d8] bg-[#faf9f5] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {isUserAuthenticated ? (
            <Database className="w-4 h-4 text-[#ea4e1b]" />
          ) : (
            <History className="w-4 h-4 text-[#ea4e1b]" />
          )}
          <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
            {isUserAuthenticated
              ? "Persistent Investigation Dossier Ledger"
              : "Session Investigation Ledger"}
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 bg-[#ffffff] border border-[#cfccc2] text-[#4d5058] font-bold">
            {isUserAuthenticated
              ? `${totalCases} SAVED CASES`
              : `${history.length} SESSION CASES`}
          </span>
          {isUserAuthenticated && (
            <span className="text-[9px] font-mono uppercase font-bold text-[#185a30] bg-[#e8f6ed] px-1.5 py-0.5 border border-[#a8dfba] hidden sm:inline-flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-[#185a30]" />
              <span>POSTGRESQL SYNCED</span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {isUserAuthenticated ? (
            <button
              onClick={() => fetchPersistentCases(page)}
              disabled={loadingCases}
              className="inline-flex items-center gap-1 text-[11px] font-mono uppercase text-[#747782] hover:text-[#ea4e1b] transition-colors cursor-pointer disabled:opacity-50"
              title="Refresh case ledger"
            >
              <RefreshCw
                className={`w-3 h-3 ${loadingCases ? "animate-spin text-[#ea4e1b]" : ""}`}
              />
              <span className="hidden sm:inline">REFRESH</span>
            </button>
          ) : (
            <button
              onClick={onClearHistory}
              className="inline-flex items-center gap-1 text-[11px] font-mono uppercase text-[#747782] hover:text-[#ea4e1b] transition-colors cursor-pointer"
            >
              <Trash2 className="w-3 h-3" />
              <span>PURGE SESSION</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Unauthenticated Notice & Call-to-Action */}
      {!isUserAuthenticated && (
        <div className="p-4 bg-[#fbf9f4] border-b border-[#e4e1d8] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-start gap-2.5">
            <Lock className="w-4 h-4 text-[#ea4e1b] shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-bold text-[#121316] uppercase tracking-wider block text-[11px]">
                ANONYMOUS OPERATOR SESSION // EPHEMERAL STORAGE
              </span>
              <p className="text-[11px] font-sans text-[#4d5058]">
                Investigation reports are currently held in browser session memory only. Sign in or register to permanently persist, paginate, and audit investigation dossiers across devices.
              </p>
            </div>
          </div>
          {onOpenAuth && (
            <button
              onClick={() => onOpenAuth("login")}
              className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#ea4e1b] hover:bg-[#d54212] text-[#ffffff] border border-[#ea4e1b] text-xs font-mono font-bold uppercase transition-colors cursor-pointer shadow-sm"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>SIGN IN TO PERSIST</span>
            </button>
          )}
        </div>
      )}

      {/* 3. Error Banner */}
      {casesError && (
        <div className="p-3.5 bg-[#fdf3ef] border-b border-[#f8ab93] text-xs font-mono text-[#ea4e1b] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-[#ea4e1b] shrink-0" />
            <span>{casesError}</span>
          </div>
          <div className="flex items-center gap-2">
            {isUserAuthenticated && (
              <button
                onClick={() => fetchPersistentCases(page)}
                className="text-[11px] underline uppercase hover:text-[#d54212] font-bold cursor-pointer"
              >
                RETRY
              </button>
            )}
            <button
              onClick={() => setCasesError(null)}
              className="text-[#747782] hover:text-[#ea4e1b] p-0.5 cursor-pointer"
              title="Dismiss error"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* 4. Ledger Content Body */}
      {isUserAuthenticated ? (
        /* Authenticated View: Persistent DB Cases */
        <div>
          {loadingCases && persistentCases.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-[#747782] flex flex-col items-center justify-center gap-2">
              <Loader2 className="w-5 h-5 text-[#ea4e1b] animate-spin" />
              <span>QUERYING ENCRYPTED AUDIT LEDGER...</span>
            </div>
          ) : persistentCases.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-[#747782] space-y-1">
              <div className="font-bold uppercase text-[#121316]">
                NO ARCHIVED DOSSIERS FOUND
              </div>
              <p className="text-[11px] font-sans text-[#4d5058]">
                Execute an SMS or URL threat investigation above. Saved cases will automatically populate this permanent cloud ledger.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#e4e1d8] max-h-96 overflow-y-auto">
              {persistentCases.map((item) => {
                const isSelected = item.case_id === currentCaseId;
                const isItemLoading = loadingCaseDetailId === item.case_id;
                const isConfirmingDelete = deletingCaseId === item.case_id;
                const { badge, icon: VerdictIcon, iconColor } = getVerdictStyle(item.verdict);

                return (
                  <div
                    key={item.case_id}
                    className={`p-3.5 sm:px-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono transition-colors ${
                      isSelected
                        ? "bg-[#faf9f5] border-l-4 border-l-[#ea4e1b]"
                        : "hover:bg-[#faf9f5] border-l-4 border-l-transparent"
                    }`}
                  >
                    {/* Left: Case Info & Clickable Trigger */}
                    <div
                      onClick={() => !isConfirmingDelete && handleSelectPersistentCase(item)}
                      className="space-y-1 overflow-hidden pr-2 flex-1 cursor-pointer"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        {isItemLoading ? (
                          <Loader2 className="w-3.5 h-3.5 text-[#ea4e1b] animate-spin shrink-0" />
                        ) : (
                          <VerdictIcon className={`w-3.5 h-3.5 ${iconColor} shrink-0`} />
                        )}
                        <span className="font-bold text-[#121316]">
                          {item.case_id}
                        </span>
                        <span className="text-[9px] font-mono uppercase bg-[#f1f3f5] text-[#525763] px-1.5 py-0.2 border border-[#c4c8d3]">
                          {item.investigation_type}
                        </span>
                        <span className="text-[10px] text-[#747782]">
                          {new Date(item.created_at).toLocaleString()}
                        </span>
                        {isSelected && (
                          <span className="text-[9px] font-mono uppercase font-bold text-[#ea4e1b] bg-[#fdf3ef] px-1.5 py-0.5 border border-[#f8ab93]">
                            ACTIVE
                          </span>
                        )}
                      </div>
                      <p className="text-[#4d5058] truncate max-w-xl text-[11px] font-sans">
                        {item.summary || "Investigation completed. Click to inspect complete threat dossier."}
                      </p>
                    </div>

                    {/* Right: Scores, Verdict, and Delete Action */}
                    <div className="flex items-center gap-3 shrink-0">
                      <div className="text-right">
                        <span className="font-mono font-bold text-[#121316] tabular-nums">
                          {item.verdict === "inconclusive"
                            ? "—"
                            : `${item.threat_score.toFixed(1)}/100`}
                        </span>
                      </div>

                      <span
                        className={`px-2 py-0.5 text-[9px] uppercase font-mono font-bold border ${badge}`}
                      >
                        {item.verdict}
                      </span>

                      {/* Delete Action with Inline Confirmation */}
                      {isConfirmingDelete ? (
                        <div className="flex items-center gap-1.5 bg-[#fdf3ef] border border-[#f8ab93] p-1">
                          <span className="text-[10px] text-[#ea4e1b] font-bold uppercase pl-1">
                            CONFIRM?
                          </span>
                          <button
                            onClick={() => handleDeletePersistentCase(item.case_id)}
                            disabled={isDeleting}
                            className="px-2 py-0.5 bg-[#ea4e1b] text-[#ffffff] text-[10px] font-bold uppercase hover:bg-[#d54212] transition-colors cursor-pointer disabled:opacity-50"
                          >
                            {isDeleting ? "..." : "YES"}
                          </button>
                          <button
                            onClick={() => setDeletingCaseId(null)}
                            disabled={isDeleting}
                            className="px-2 py-0.5 bg-[#ffffff] text-[#4d5058] border border-[#cfccc2] text-[10px] font-bold uppercase hover:bg-[#edebe4] transition-colors cursor-pointer"
                          >
                            NO
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setDeletingCaseId(item.case_id);
                          }}
                          className="p-1 text-[#747782] hover:text-[#ea4e1b] transition-colors cursor-pointer"
                          title="Delete case dossier"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}

                      <button
                        onClick={() => handleSelectPersistentCase(item)}
                        className="p-1 text-[#747782] hover:text-[#ea4e1b] transition-colors cursor-pointer hidden sm:block"
                        title="Load dossier"
                      >
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* 5. Pagination Bar */}
          {totalPages > 1 && (
            <div className="px-5 py-2.5 border-t border-[#e4e1d8] bg-[#faf9f5] flex items-center justify-between text-xs font-mono">
              <span className="text-[11px] text-[#747782]">
                PAGE <strong className="text-[#121316]">{page}</strong> OF{" "}
                <strong className="text-[#121316]">{totalPages}</strong> ({totalCases} TOTAL CASES)
              </span>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1 || loadingCases}
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#ffffff] border border-[#cfccc2] text-[#121316] hover:bg-[#edebe4] disabled:opacity-40 transition-colors cursor-pointer disabled:cursor-not-allowed text-[11px] font-bold uppercase"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>PREV</span>
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages || loadingCases}
                  className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#ffffff] border border-[#cfccc2] text-[#121316] hover:bg-[#edebe4] disabled:opacity-40 transition-colors cursor-pointer disabled:cursor-not-allowed text-[11px] font-bold uppercase"
                >
                  <span>NEXT</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Unauthenticated View: Local Session History */
        <div>
          {history.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-[#747782] space-y-1">
              <div className="font-bold uppercase text-[#121316]">
                NO ACTIVE SESSION CASES
              </div>
              <p className="text-[11px] font-sans text-[#4d5058]">
                Ingest an SMS message or embedded URL above to initiate passive threat triage.
              </p>
            </div>
          ) : (
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
          )}
        </div>
      )}

      {/* 6. Footer Disclaimer Bar */}
      <div className="px-5 py-2 border-t border-[#e4e1d8] bg-[#faf9f5] text-[10px] font-mono text-[#747782] flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>
          {isUserAuthenticated
            ? "Private dossiers encrypted and isolated per authenticated operator ID • Permanent retention until manually deleted"
            : "Ledger preserved in browser session storage only • Zero backend log retention"}
        </span>
        <span className="text-[#4d5058] font-bold">PHISHLENS v1.0</span>
      </div>
    </section>
  );
};
