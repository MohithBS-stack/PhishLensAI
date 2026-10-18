"""Pydantic schemas for PhishLens AI multimodal scanning endpoints."""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.ml.inference import MessagePredictionResult, URLPredictionResult
from app.schemas.evidence import StructuredExplanation


class ThreatIndicator(BaseModel):
    """Specific threat or suspicious signal identified during analysis."""
    indicator_type: str = Field(description="Category (e.g., 'urgency_keyword', 'suspicious_url', 'obfuscation')")
    name: str = Field(description="Short human-readable signal name")
    severity: str = Field(description="'low', 'medium', 'high', 'critical'")
    description: str = Field(description="Explanation of why this indicator is suspicious")
    evidence: Optional[str] = Field(default=None, description="Triggering snippet or matched text")


class URLScanSummary(BaseModel):
    """Summary of a scanned URL found in content."""
    url: str
    is_phishing: bool
    confidence: float
    label: str
    phishing_probability: float
    extracted_features: Dict[str, Any]


class MessageAnalysisReport(BaseModel):
    """Unified message and text threat analysis report."""
    text: str = Field(description="Analyzed text content")
    label: str = Field(description="'spam' or 'ham'")
    is_suspicious: bool = Field(description="True if flagged as spam, suspicious, or contains phishing URLs")
    confidence: float = Field(description="Confidence score (0.0 - 1.0)")
    risk_score: float = Field(description="Composite risk score (0.0 - 100.0)")
    severity: str = Field(description="'low', 'medium', 'high', or 'critical'")
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list, description="Extracted URLs (analyzed passively)")
    url_evaluations: List[URLScanSummary] = Field(default_factory=list)
    explanation: Optional[StructuredExplanation] = Field(default=None, description="Optional evidence-grounded threat explanation")


class TextScanRequest(BaseModel):
    """Request payload for direct text/SMS scanning."""
    text: str = Field(..., min_length=1, max_length=10000, description="Message text to analyze")
    include_explanation: bool = Field(default=False, description="Whether to include structured threat explanation")


class URLScanRequest(BaseModel):
    """Request payload for direct URL scanning."""
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to analyze passively")
    include_explanation: bool = Field(default=True, description="Whether to include structured threat explanation")


class URLScanResponse(BaseModel):
    """Direct URL scanning response with passive evaluation and optional explanation."""
    url: str
    is_phishing: bool
    confidence: float
    label: str
    phishing_probability: float
    risk_score: float
    severity: str
    extracted_features: Dict[str, Any]
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list)
    explanation: Optional[StructuredExplanation] = Field(default=None, description="Optional evidence-grounded threat explanation")


class ScreenshotAnalysisResponse(BaseModel):
    """Response payload for screenshot OCR and threat analysis."""
    modality: str = Field(default="screenshot", description="Source modality")
    filename: str = Field(description="Original uploaded file name")
    content_type: str = Field(description="Validated MIME type (image/png, image/jpeg)")
    size_bytes: int = Field(description="File size in bytes")
    image_width: int = Field(description="Image width in pixels")
    image_height: int = Field(description="Image height in pixels")
    extracted_text: str = Field(description="Raw text extracted via OCR")
    ocr_engine: str = Field(description="OCR engine utilized")
    message_analysis: MessageAnalysisReport = Field(description="Threat evaluation of extracted text")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Structured forensic evidence")


class AudioAnalysisResponse(BaseModel):
    """Response payload for audio speech-to-text and threat analysis."""
    modality: str = Field(default="audio", description="Source modality")
    filename: str = Field(description="Original uploaded file name")
    content_type: str = Field(description="Validated MIME type (audio/wav, audio/mpeg, etc.)")
    size_bytes: int = Field(description="File size in bytes")
    duration_seconds: float = Field(description="Audio duration in seconds")
    sample_rate: int = Field(description="Audio sample rate (Hz)")
    channels: int = Field(description="Audio channel count")
    transcript: str = Field(description="Transcribed spoken text")
    stt_engine: str = Field(description="Speech-to-text engine utilized")
    message_analysis: MessageAnalysisReport = Field(description="Threat evaluation of transcript")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Structured forensic evidence")
    disclaimer: str = Field(
        default="PhishLens AI performs text-based scam and threat analysis on transcribed speech. It does not detect synthetic voices, voice cloning, or deepfakes.",
        description="Audio analysis scope disclaimer"
    )


# Re-export Phase 4 Unified Evidence & Threat schemas for convenience
from app.schemas.evidence import (  # noqa: E402
    NormalizedEvidence,
    ManipulationTactic,
    StructuredExplanation,
    UncertaintyReport,
    UnifiedScanRequest,
    UnifiedReportResponse,
)
