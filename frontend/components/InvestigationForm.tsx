"use client";

import React, { useState, useEffect } from "react";
import {
  FileText,
  Globe,
  Image as ImageIcon,
  Mic,
  Upload,
  Trash2,
  Sparkles,
  AlertTriangle,
  ArrowRight,
  Shield,
  Layers,
  Cpu,
  CheckCircle2,
  X,
} from "lucide-react";

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
  const [pipelineStage, setPipelineStage] = useState(0);

  // File size limits in bytes
  const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
  const MAX_AUDIO_SIZE = 25 * 1024 * 1024; // 25MB

  // Simulated active pipeline stage during real scan request
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (loading) {
      setPipelineStage(0);
      interval = setInterval(() => {
        setPipelineStage((prev) => (prev < 4 ? prev + 1 : prev));
      }, 1200);
    } else {
      setPipelineStage(0);
    }
    return () => clearInterval(interval);
  }, [loading]);

  const handleScreenshotChange = (file: File | null) => {
    setValidationError(null);
    if (!file) {
      setScreenshotFile(null);
      return;
    }
    if (!file.type.startsWith("image/")) {
      setValidationError("Invalid screenshot file. Accepted formats: PNG, JPG, JPEG.");
      return;
    }
    if (file.size > MAX_IMAGE_SIZE) {
      setValidationError("Screenshot exceeds maximum limit of 10MB.");
      return;
    }
    setScreenshotFile(file);
  };

  const handleAudioChange = (file: File | null) => {
    setValidationError(null);
    if (!file) {
      setAudioFile(null);
      return;
    }
    if (!file.type.startsWith("audio/") && !file.name.match(/\.(wav|mp3|m4a|ogg|flac)$/i)) {
      setValidationError("Invalid audio file. Accepted formats: WAV, MP3, M4A, OGG, FLAC.");
      return;
    }
    if (file.size > MAX_AUDIO_SIZE) {
      setValidationError("Audio recording exceeds maximum limit of 25MB.");
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

  const handleRunInvestigation = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (loading) return;
    setValidationError(null);

    const parsedUrls = parseUrls(urlsInput);
    const hasText = text.trim().length > 0;
    const hasUrls = parsedUrls.length > 0;
    const hasImage = Boolean(screenshotFile);
    const hasAudio = Boolean(audioFile);

    if (!hasText && !hasUrls && !hasImage && !hasAudio) {
      setValidationError("At least one evidence modality (Text, URLs, Screenshot, or Audio) is required to initiate an investigation.");
      return;
    }

    // Low latency JSON endpoint if only text & URLs
    if (!hasImage && !hasAudio) {
      onSubmitJson({
        text: hasText ? text.trim() : undefined,
        urls: hasUrls ? parsedUrls : undefined,
        include_explanation: includeExplanation,
      });
      return;
    }

    // Multipart investigation for binary files
    const formData = new FormData();
    if (hasText) formData.append("text", text.trim());
    if (hasUrls) formData.append("urls", parsedUrls.join(","));
    if (screenshotFile) formData.append("screenshot", screenshotFile);
    if (audioFile) formData.append("audio", audioFile);
    formData.append("include_explanation", includeExplanation ? "true" : "false");

    onSubmitMultimodal(formData);
  };

  // Keyboard shortcut: Cmd+Enter or Ctrl+Enter to run investigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      handleRunInvestigation();
    }
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

  const pipelineStages = [
    { label: "EVIDENCE INGESTION", desc: "Validating input streams & payload schema" },
    { label: "CONTENT EXTRACTION", desc: "Lexical tokens, OCR text & audio transcript" },
    { label: "MODEL INFERENCE", desc: "Executing SMS Classifier & PhiUSIIL URL models" },
    { label: "RISK FUSION", desc: "Evaluating manipulation tactics & dampening" },
    { label: "DOSSIER SYNTHESIS", desc: "Assembling calibrated forensic report" },
  ];

  return (
    <section className="bg-[#ffffff] border border-[#cfccc2] shadow-sm">
      {/* Workspace Header Bar */}
      <div className="px-5 py-4 border-b border-[#e4e1d8] flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#faf9f5]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono tracking-widest text-[#ea4e1b] uppercase font-bold">
              [INTAKE WORKSPACE]
            </span>
            <span className="text-xs text-[#747782] font-mono">
              // MULTI-MODALITY EVIDENCE INGESTION
            </span>
          </div>
          <h2 className="text-base sm:text-lg font-mono font-bold tracking-tight text-[#121316] mt-0.5">
            Submit Threat Artifacts for Passive Evaluation
          </h2>
        </div>

        {/* Tactical Preset Loaders */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-mono tracking-wider uppercase text-[#747782] mr-1 hidden sm:inline">
            TEST SCENARIOS:
          </span>
          <button
            type="button"
            onClick={() => loadPreset("paypal")}
            className="px-2.5 py-1 text-[11px] font-mono uppercase bg-[#ffffff] hover:bg-[#fdf3ef] text-[#ea4e1b] border border-[#f8ab93] transition-colors cursor-pointer font-semibold"
          >
            PayPal Phish
          </button>
          <button
            type="button"
            onClick={() => loadPreset("irs")}
            className="px-2.5 py-1 text-[11px] font-mono uppercase bg-[#ffffff] hover:bg-[#fef8ee] text-[#b45309] border border-[#fcd38d] transition-colors cursor-pointer font-semibold"
          >
            IRS Coercion
          </button>
          <button
            type="button"
            onClick={() => loadPreset("clean")}
            className="px-2.5 py-1 text-[11px] font-mono uppercase bg-[#ffffff] hover:bg-[#eff8f3] text-[#177846] border border-[#9ed4b9] transition-colors cursor-pointer font-semibold"
          >
            Benign Memo
          </button>
          <button
            type="button"
            onClick={clearForm}
            title="Clear all fields"
            className="p-1 text-[#747782] hover:text-[#121316] border border-transparent hover:border-[#cfccc2] transition-colors cursor-pointer ml-1"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <form onSubmit={handleRunInvestigation} onKeyDown={handleKeyDown} className="p-5 sm:p-6 space-y-6">
        {/* Modality Mode Selector Tabs */}
        <div className="flex items-center gap-1 border-b border-[#e4e1d8] pb-3">
          <button
            type="button"
            onClick={() => setActiveTab("multimodal")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-semibold uppercase tracking-wider transition-colors cursor-pointer ${
              activeTab === "multimodal"
                ? "bg-[#111215] text-[#f6f5f0] border border-[#111215]"
                : "bg-[#f6f5f0] text-[#4d5058] border border-[#e4e1d8] hover:bg-[#edebe4]"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Multimodal Intake (Text + URLs + OCR + Audio)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("text_url")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-semibold uppercase tracking-wider transition-colors cursor-pointer ${
              activeTab === "text_url"
                ? "bg-[#111215] text-[#f6f5f0] border border-[#111215]"
                : "bg-[#f6f5f0] text-[#4d5058] border border-[#e4e1d8] hover:bg-[#edebe4]"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Lexical &amp; URL Fastpath Only</span>
          </button>
        </div>

        {/* Input Section Grid: Message Body + Target URLs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Message / SMS Body Text Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label
                htmlFor="message-text"
                className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase tracking-wider text-[#121316]"
              >
                <FileText className="w-3.5 h-3.5 text-[#ea4e1b]" />
                <span>Message / Email / SMS Text Content</span>
              </label>
              <span className="text-[10px] font-mono text-[#747782] tabular-nums">
                {text.length} / 20,000 CHARS
              </span>
            </div>
            <textarea
              id="message-text"
              rows={5}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste suspicious SMS, email body, urgency alert, or chat snippet here..."
              className="w-full bg-[#faf9f5] border border-[#cfccc2] p-3 text-xs sm:text-sm text-[#121316] placeholder-[#747782] focus:bg-[#ffffff] focus:border-[#ea4e1b] focus:outline-none font-mono resize-y transition-colors"
            />
            <p className="text-[10px] font-mono text-[#747782]">
              Evaluated by Model A (SMS classifier) &amp; psychological manipulation heuristic detector.
            </p>
          </div>

          {/* Standalone Target URLs Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label
                htmlFor="urls-input"
                className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase tracking-wider text-[#121316]"
              >
                <Globe className="w-3.5 h-3.5 text-[#ea4e1b]" />
                <span>Target URLs (Comma or Line Separated)</span>
              </label>
              <span className="text-[10px] font-mono text-[#747782]">
                PASSIVE ANALYSIS
              </span>
            </div>
            <textarea
              id="urls-input"
              rows={5}
              value={urlsInput}
              onChange={(e) => setUrlsInput(e.target.value)}
              placeholder="e.g. http://secure-login-update.xyz, https://service-portal.com"
              className="w-full bg-[#faf9f5] border border-[#cfccc2] p-3 text-xs sm:text-sm text-[#121316] placeholder-[#747782] focus:bg-[#ffffff] focus:border-[#ea4e1b] focus:outline-none font-mono resize-y transition-colors"
            />
            <p className="text-[10px] font-mono text-[#747782]">
              Embedded links in the text are also extracted automatically. Domains are never contacted directly.
            </p>
          </div>
        </div>

        {/* Multimodal Binary Ingestion (Screenshots + Audio Recordings) */}
        {activeTab === "multimodal" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5 pt-2 border-t border-[#e4e1d8]">
            {/* Screenshot OCR Dropzone */}
            <div className="border border-[#cfccc2] bg-[#faf9f5] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
                    <ImageIcon className="w-3.5 h-3.5 text-[#ea4e1b]" />
                    <span>Screenshot OCR Stream</span>
                  </span>
                  <span className="text-[10px] font-mono text-[#747782]">MAX 10MB</span>
                </div>
                <p className="text-[11px] text-[#4d5058] mb-3">
                  Upload PNG or JPG captures of suspicious emails, login prompts, or SMS screenshots.
                </p>

                {screenshotFile ? (
                  <div className="bg-[#ffffff] border border-[#cfccc2] p-2.5 flex items-center justify-between">
                    <div className="flex items-center gap-2 overflow-hidden">
                      <ImageIcon className="w-4 h-4 text-[#ea4e1b] shrink-0" />
                      <div className="truncate text-xs font-mono">
                        <span className="font-semibold text-[#121316]">{screenshotFile.name}</span>
                        <span className="text-[#747782] ml-1.5">
                          ({(screenshotFile.size / 1024).toFixed(0)} KB)
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setScreenshotFile(null)}
                      className="text-[#747782] hover:text-[#ea4e1b] p-1 cursor-pointer"
                      title="Remove file"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <label className="border-2 border-dashed border-[#cfccc2] hover:border-[#ea4e1b] bg-[#ffffff] p-4 flex flex-col items-center justify-center gap-1.5 cursor-pointer transition-colors text-center">
                    <Upload className="w-4 h-4 text-[#747782]" />
                    <span className="text-xs font-mono font-semibold text-[#121316]">
                      Click or drop image file
                    </span>
                    <span className="text-[10px] font-mono text-[#747782]">
                      PNG, JPG, JPEG (processed in memory)
                    </span>
                    <input
                      type="file"
                      accept="image/png,image/jpeg,image/jpg"
                      onChange={(e) => handleScreenshotChange(e.target.files?.[0] || null)}
                      className="hidden"
                    />
                  </label>
                )}
              </div>
              <div className="text-[9px] font-mono text-[#747782] uppercase mt-2">
                Processed via Tesseract OCR • Zero persistent disk storage
              </div>
            </div>

            {/* Audio Recording Dropzone */}
            <div className="border border-[#cfccc2] bg-[#faf9f5] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="flex items-center gap-1.5 text-xs font-mono font-bold uppercase tracking-wider text-[#121316]">
                    <Mic className="w-3.5 h-3.5 text-[#ea4e1b]" />
                    <span>Voicemail / Audio Stream</span>
                  </span>
                  <span className="text-[10px] font-mono text-[#747782]">MAX 25MB</span>
                </div>
                <p className="text-[11px] text-[#4d5058] mb-3">
                  Upload WAV, MP3, or M4A audio from suspicious calls, robocalls, or vishing voicemail.
                </p>

                {audioFile ? (
                  <div className="bg-[#ffffff] border border-[#cfccc2] p-2.5 flex items-center justify-between">
                    <div className="flex items-center gap-2 overflow-hidden">
                      <Mic className="w-4 h-4 text-[#ea4e1b] shrink-0" />
                      <div className="truncate text-xs font-mono">
                        <span className="font-semibold text-[#121316]">{audioFile.name}</span>
                        <span className="text-[#747782] ml-1.5">
                          ({(audioFile.size / 1024).toFixed(0)} KB)
                        </span>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setAudioFile(null)}
                      className="text-[#747782] hover:text-[#ea4e1b] p-1 cursor-pointer"
                      title="Remove file"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ) : (
                  <label className="border-2 border-dashed border-[#cfccc2] hover:border-[#ea4e1b] bg-[#ffffff] p-4 flex flex-col items-center justify-center gap-1.5 cursor-pointer transition-colors text-center">
                    <Upload className="w-4 h-4 text-[#747782]" />
                    <span className="text-xs font-mono font-semibold text-[#121316]">
                      Click or drop audio file
                    </span>
                    <span className="text-[10px] font-mono text-[#747782]">
                      WAV, MP3, M4A, OGG, FLAC
                    </span>
                    <input
                      type="file"
                      accept="audio/wav,audio/mpeg,audio/mp3,audio/m4a,audio/ogg"
                      onChange={(e) => handleAudioChange(e.target.files?.[0] || null)}
                      className="hidden"
                    />
                  </label>
                )}
              </div>
              <div className="text-[9px] font-mono text-[#747782] uppercase mt-2">
                Processed via Whisper Speech-to-Text • Ephemeral buffer
              </div>
            </div>
          </div>
        )}

        {/* Dynamic Investigation Pipeline Visualization (During Active Scan) */}
        {loading && (
          <div className="border border-[#111215] bg-[#111215] text-[#f6f5f0] p-4 sm:p-5 relative overflow-hidden">
            {/* Visual scanline effect */}
            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#ea4e1b]/10 to-transparent h-16 w-full animate-scanline pointer-events-none" />

            <div className="flex items-center justify-between pb-3 border-b border-[#27282f] mb-4">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[#ea4e1b] animate-ping" />
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-[#ea4e1b]">
                  INVESTIGATION PIPELINE IN EXECUTION
                </span>
              </div>
              <span className="text-[10px] font-mono text-[#9a9ca8] uppercase">
                ILLUSTRATIVE PROCESSING STAGES // LIVE REQUEST DISPATCHED
              </span>
            </div>

            {/* 5-Stage Sequential Pipeline Diagram */}
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-xs font-mono">
              {pipelineStages.map((stg, idx) => {
                const isComplete = idx < pipelineStage;
                const isCurrent = idx === pipelineStage;
                return (
                  <div
                    key={stg.label}
                    className={`p-2.5 border transition-all ${
                      isCurrent
                        ? "border-[#ea4e1b] bg-[#18191d] text-[#ffffff]"
                        : isComplete
                        ? "border-[#1d4731] bg-[#14231b] text-[#9ed4b9]"
                        : "border-[#27282f] bg-[#141518] text-[#747782]"
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] mb-1">
                      <span>0{idx + 1}</span>
                      {isComplete ? (
                        <CheckCircle2 className="w-3 h-3 text-[#177846]" />
                      ) : isCurrent ? (
                        <Cpu className="w-3 h-3 text-[#ea4e1b] animate-pulse" />
                      ) : null}
                    </div>
                    <div className="font-bold tracking-tight text-[11px]">{stg.label}</div>
                    <div className="text-[9px] text-[#9a9ca8] mt-1 leading-snug">{stg.desc}</div>
                  </div>
                );
              })}
            </div>

            <div className="text-[9px] font-mono text-[#747782] uppercase mt-3">
              Illustrative processing sequence • Awaiting complete response from FastAPI inference engine
            </div>
          </div>
        )}

        {/* Validation Error Banner */}
        {validationError && (
          <div className="p-3.5 bg-[#fdf3ef] border border-[#f8ab93] text-xs font-mono text-[#ea4e1b] flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                <strong className="uppercase">VALIDATION ERROR:</strong> {validationError}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setValidationError(null)}
              className="p-1 hover:bg-[#ffffff] text-[#ea4e1b] cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Controls & Submission Bar */}
        <div className="pt-2 border-t border-[#e4e1d8] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <label className="flex items-center gap-2.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeExplanation}
              onChange={(e) => setIncludeExplanation(e.target.checked)}
              className="accent-[#ea4e1b] h-4 w-4 rounded-none cursor-pointer"
            />
            <div className="flex items-center gap-1.5 text-xs font-mono text-[#121316]">
              <Sparkles className="w-3.5 h-3.5 text-[#ea4e1b]" />
              <span>Generate AI Grounded Executive Briefing (Gemini)</span>
            </div>
          </label>

          <div className="flex items-center gap-3">
            <span className="hidden lg:inline text-[10px] font-mono text-[#747782] uppercase">
              SHORTCUT: ⌘+ENTER / CTRL+ENTER
            </span>
            <button
              type="submit"
              disabled={loading}
              className={`w-full sm:w-auto px-6 py-2.5 font-mono font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                loading
                  ? "bg-[#cfccc2] text-[#747782] cursor-not-allowed border border-[#cfccc2]"
                  : "bg-[#ea4e1b] hover:bg-[#d54212] text-[#ffffff] border border-[#ea4e1b] shadow-sm hover:shadow cursor-pointer active:translate-y-px"
              }`}
            >
              {loading ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin" />
                  <span>ANALYZING EVIDENCE...</span>
                </>
              ) : (
                <>
                  <span>EXECUTE INVESTIGATION</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </section>
  );
};
