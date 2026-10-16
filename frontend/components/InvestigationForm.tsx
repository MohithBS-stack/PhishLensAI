"use client";

import React, { useState } from "react";

interface InvestigationFormProps {
  onSubmitJson: (payload: {
    text?: string;
    urls?: string[];
    include_explanation: boolean;
  }) => void;
  onSubmitMultimodal: (formData: FormData) => void;
  loading: boolean;
}

export const InvestigationForm: React.FC<InvestigationFormProps> = ({
  onSubmitJson,
  onSubmitMultimodal,
  loading,
}) => {
  const [activeTab, setActiveTab] = useState<"multimodal" | "text_url">("multimodal");
  const [text, setText] = useState("");
  const [urlsInput, setUrlsInput] = useState("");
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [includeExplanation, setIncludeExplanation] = useState(true);
  const [validationError, setValidationError] = useState<string | null>(null);

  // File size limits in bytes
  const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
  const MAX_AUDIO_SIZE = 25 * 1024 * 1024; // 25MB

  const handleScreenshotChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValidationError(null);
    const file = e.target.files?.[0];
    if (!file) {
      setScreenshotFile(null);
      return;
    }
    if (!file.type.startsWith("image/")) {
      setValidationError("Invalid screenshot file. Allowed types: PNG, JPG, JPEG.");
      return;
    }
    if (file.size > MAX_IMAGE_SIZE) {
      setValidationError("Screenshot exceeds maximum limit of 10MB.");
      return;
    }
    setScreenshotFile(file);
  };

  const handleAudioChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValidationError(null);
    const file = e.target.files?.[0];
    if (!file) {
      setAudioFile(null);
      return;
    }
    if (!file.type.startsWith("audio/") && !file.name.match(/\.(wav|mp3|m4a|ogg|flac)$/i)) {
      setValidationError("Invalid audio file. Allowed types: WAV, MP3, M4A, OGG, FLAC.");
      return;
    }
    if (file.size > MAX_AUDIO_SIZE) {
      setValidationError("Audio file exceeds maximum limit of 25MB.");
      return;
    }
    setAudioFile(file);
  };

  const parseUrls = (input: string): string[] => {
    return input
      .split(/[\n,]+/)
      .map((u) => u.trim())
      .filter((u) => u.length > 0);
  };

  const handleRunInvestigation = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);

    const parsedUrls = parseUrls(urlsInput);
    const hasText = text.trim().length > 0;
    const hasUrls = parsedUrls.length > 0;
    const hasImage = Boolean(screenshotFile);
    const hasAudio = Boolean(audioFile);

    if (!hasText && !hasUrls && !hasImage && !hasAudio) {
      setValidationError("Please provide at least one input modality (Text, URLs, Screenshot, or Audio) to analyze.");
      return;
    }

    // If only text/URLs and no files, use JSON endpoint for lowest latency
    if (!hasImage && !hasAudio) {
      onSubmitJson({
        text: hasText ? text.trim() : undefined,
        urls: hasUrls ? parsedUrls : undefined,
        include_explanation: includeExplanation,
      });
      return;
    }

    // Otherwise use multipart investigate endpoint
    const formData = new FormData();
    if (hasText) formData.append("text", text.trim());
    if (hasUrls) formData.append("urls", parsedUrls.join(","));
    if (screenshotFile) formData.append("screenshot", screenshotFile);
    if (audioFile) formData.append("audio", audioFile);
    formData.append("include_explanation", includeExplanation ? "true" : "false");

    onSubmitMultimodal(formData);
  };

  // Preset loaders for instant demonstrations
  const loadPreset = (type: "paypal" | "irs" | "clean") => {
    setValidationError(null);
    setScreenshotFile(null);
    setAudioFile(null);

    if (type === "paypal") {
      setText(
        "URGENT: PayPal Security Team Alert. Your account will be suspended within 24 hours due to suspicious login attempts. Verify your identity immediately or your access will be permanently terminated."
      );
      setUrlsInput("http://paypal-verification-center.xyz/login");
    } else if (type === "irs") {
      setText(
        "FINAL NOTICE: Internal Revenue Service (IRS) Criminal Investigation. You have an overdue tax penalty. You must purchase Steam gift cards or arrange an immediate wire transfer to avoid arrest. Do not contact your local bank or speak with anyone regarding this matter."
      );
      setUrlsInput("");
    } else {
      setText(
        "Hey Marcus, here is the draft architecture proposal for the quarterly security review. Let's discuss tomorrow during our sync."
      );
      setUrlsInput("https://www.southbankmosaics.com");
    }
  };

  const clearForm = () => {
    setText("");
    setUrlsInput("");
    setScreenshotFile(null);
    setAudioFile(null);
    setValidationError(null);
  };

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur-xl p-5 sm:p-7 shadow-2xl transition-all">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-5 border-b border-slate-800/80 gap-3">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            Investigation Workspace
          </h2>
          <p className="text-xs text-slate-400">
            Combine text, suspicious links, screenshots, or voicemail audio into one fused investigation
          </p>
        </div>

        {/* Demo Preset Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-slate-400 mr-1 hidden lg:inline">Presets:</span>
          <button
            type="button"
            onClick={() => loadPreset("paypal")}
            className="px-2.5 py-1 text-xs rounded-lg font-medium bg-rose-950/60 text-rose-300 border border-rose-800/60 hover:bg-rose-900/60 transition-colors"
          >
            PayPal Phish
          </button>
          <button
            type="button"
            onClick={() => loadPreset("irs")}
            className="px-2.5 py-1 text-xs rounded-lg font-medium bg-amber-950/60 text-amber-300 border border-amber-800/60 hover:bg-amber-900/60 transition-colors"
          >
            IRS Scam
          </button>
          <button
            type="button"
            onClick={() => loadPreset("clean")}
            className="px-2.5 py-1 text-xs rounded-lg font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60 transition-colors"
          >
            Benign
          </button>
          <button
            type="button"
            onClick={clearForm}
            className="px-2 py-1 text-xs rounded-lg font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      <form onSubmit={handleRunInvestigation} className="mt-5 space-y-5">
        {/* Modality Mode Pills */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <button
            type="button"
            onClick={() => setActiveTab("multimodal")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "multimodal"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Full Multimodal (Text + URL + Image + Audio)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("text_url")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === "text_url"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Text &amp; URL Only
          </button>
        </div>

        {/* Message / SMS Body Text Input */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="message-text" className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Message / Email / SMS Text Content
            </label>
            <span className="text-[11px] font-mono text-slate-500">
              {text.length} / 20,000 characters
            </span>
          </div>
          <textarea
            id="message-text"
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste suspicious SMS, email body, urgency alert, or chat snippet here..."
            className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-sans transition-all resize-y"
          />
        </div>

        {/* Standalone or Embedded URLs Input */}
        <div>
          <label htmlFor="urls-input" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
            Explicit Target URLs (Optional, comma-separated or one per line)
          </label>
          <input
            id="urls-input"
            type="text"
            value={urlsInput}
            onChange={(e) => setUrlsInput(e.target.value)}
            placeholder="e.g. http://secure-login-update.xyz, https://example.com"
            className="w-full rounded-xl border border-slate-800 bg-slate-950/80 px-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono transition-all"
          />
          <p className="text-[11px] text-slate-500 mt-1">
            Note: Embedded links inside the message body are also automatically extracted and analyzed passively without visiting.
          </p>
        </div>

        {/* Multimodal File Uploads (Only when activeTab === 'multimodal') */}
        {activeTab === "multimodal" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            {/* Screenshot Upload Card */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Screenshot OCR Upload
              </label>
              <p className="text-[11px] text-slate-500 mb-2.5">
                PNG, JPG, or JPEG up to 10MB (processed in-memory, zero disk storage)
              </p>
              <input
                type="file"
                accept="image/png,image/jpeg,image/jpg"
                onChange={handleScreenshotChange}
                className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer"
              />
              {screenshotFile && (
                <div className="mt-2 text-xs text-cyan-400 flex items-center justify-between">
                  <span>Selected: {screenshotFile.name} ({(screenshotFile.size / 1024).toFixed(0)} KB)</span>
                  <button
                    type="button"
                    onClick={() => setScreenshotFile(null)}
                    className="text-slate-500 hover:text-slate-300 text-xs ml-2"
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>

            {/* Audio Upload Card */}
            <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-4">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Audio Recording / Voicemail (STT)
              </label>
              <p className="text-[11px] text-slate-500 mb-2.5">
                WAV, MP3, M4A up to 25MB (max 5 minutes, zero audio retention)
              </p>
              <input
                type="file"
                accept="audio/wav,audio/mpeg,audio/mp3,audio/m4a,audio/ogg"
                onChange={handleAudioChange}
                className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer"
              />
              {audioFile && (
                <div className="mt-2 text-xs text-cyan-400 flex items-center justify-between">
                  <span>Selected: {audioFile.name} ({(audioFile.size / 1024).toFixed(0)} KB)</span>
                  <button
                    type="button"
                    onClick={() => setAudioFile(null)}
                    className="text-slate-500 hover:text-slate-300 text-xs ml-2"
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Settings Toggle & Validation Error Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeExplanation}
              onChange={(e) => setIncludeExplanation(e.target.checked)}
              className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-950 h-4 w-4"
            />
            <span className="text-xs text-slate-300">
              Generate Evidence-Grounded Threat Explanation
            </span>
          </label>

          <button
            type="submit"
            disabled={loading}
            className={`w-full sm:w-auto px-6 py-2.5 rounded-xl font-bold text-sm text-slate-950 transition-all shadow-lg flex items-center justify-center gap-2 ${
              loading
                ? "bg-cyan-600/60 cursor-not-allowed"
                : "bg-cyan-400 hover:bg-cyan-300 hover:shadow-cyan-500/25 cursor-pointer active:scale-[0.98]"
            }`}
          >
            {loading ? (
              <>
                <svg
                  className="animate-spin h-4 w-4 text-slate-950"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v8H4z"
                  />
                </svg>
                <span>Analyzing Threat Vectors...</span>
              </>
            ) : (
              <span>Run Unified Investigation</span>
            )}
          </button>
        </div>

        {validationError && (
          <div className="p-3.5 rounded-xl bg-rose-950/60 border border-rose-800/80 text-xs text-rose-300 flex items-center gap-2">
            <span className="font-bold">Validation:</span>
            <span>{validationError}</span>
          </div>
        )}
      </form>
    </div>
  );
};
