"""Multimodal scanning and threat analysis API endpoints."""
from fastapi import APIRouter, File, UploadFile, status, Header
from typing import Optional

from app.schemas.scan import (
    TextScanRequest,
    MessageAnalysisReport,
    URLScanRequest,
    URLScanResponse,
    ThreatIndicator,
    ScreenshotAnalysisResponse,
    AudioAnalysisResponse,
)
from app.services.message_analysis import message_analysis_service
from app.services.ocr_service import ocr_service
from app.services.audio_service import audio_service
from app.services.explanation_service import explanation_service
from app.schemas.evidence import NormalizedEvidence
from app.ml.inference import inference_engine
import uuid

router = APIRouter(prefix="/scan", tags=["Scanning & Threat Analysis"])


@router.post(
    "/text",
    response_model=MessageAnalysisReport,
    status_code=status.HTTP_200_OK,
    summary="Scan Message / SMS Text",
    description="Analyzes message text for spam/smishing patterns, passively extracts embedded URLs, and scores overall threat severity.",
)
async def scan_text(payload: TextScanRequest) -> MessageAnalysisReport:
    """Performs unified text threat analysis with optional explanation."""
    report = message_analysis_service.analyze_message(payload.text)
    if payload.include_explanation:
        verdict = (
            "high-risk"
            if report.severity in ("critical", "high")
            else ("suspicious" if report.severity == "medium" else "benign")
        )
        evidence_items = []
        for ind in report.threat_indicators:
            evidence_items.append(
                NormalizedEvidence(
                    evidence_id=f"ev-txt-{uuid.uuid4().hex[:8]}",
                    source_modality="text",
                    indicator_type=ind.indicator_type,
                    description=ind.description,
                    supporting_excerpt=ind.evidence or ind.name,
                    severity=ind.severity,
                    evidence_source="message_analysis_service",
                    confidence=report.confidence,
                    observed_versus_inferred="inferred",
                    limitations_and_missing_checks=[],
                )
            )
        safe_steps = (
            [
                "Do not click links or reply with personal credentials.",
                "Verify the request through a trusted, independent phone number or channel.",
            ]
            if report.is_suspicious
            else [
                "Message exhibits typical benign communication patterns.",
                "Exercise standard caution with unsolicited contacts.",
            ]
        )
        report.explanation = await explanation_service.generate_explanation(
            verdict=verdict,
            score=report.risk_score,
            tactics=[],
            evidence_items=evidence_items,
            safe_next_steps=safe_steps,
            untrusted_text=payload.text,
            model_signals={"message_classifier": {"label": report.label, "confidence": report.confidence}},
        )
    return report


@router.post(
    "/url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan URL Directly",
    description="Passively analyzes a URL using the lexical classifier without visiting or making network requests to the target.",
)
async def scan_url(payload: URLScanRequest) -> URLScanResponse:
    """Performs direct passive URL threat analysis with optional explanation."""
    url_str = payload.url.strip()
    result = inference_engine.predict_url(url_str)

    risk_score = round(result.phishing_probability * 100.0, 1)
    if risk_score >= 80.0 or (result.is_phishing and result.confidence >= 0.75):
        severity = "critical"
        verdict = "high-risk"
    elif risk_score >= 55.0 or result.is_phishing:
        severity = "high"
        verdict = "high-risk"
    elif risk_score >= 30.0:
        severity = "medium"
        verdict = "suspicious"
    else:
        severity = "low"
        verdict = "benign"

    indicators: List[ThreatIndicator] = []
    if result.is_phishing:
        indicators.append(
            ThreatIndicator(
                indicator_type="phishing_url",
                name="Phishing URL Detected",
                severity="critical" if result.confidence >= 0.75 else "high",
                description=f"URL exhibited lexical characteristics of phishing ({result.confidence * 100:.1f}% confidence)",
                evidence=url_str,
            )
        )

    explanation = None
    if payload.include_explanation:
        url_evidence = NormalizedEvidence(
            evidence_id=f"ev-url-{uuid.uuid4().hex[:8]}",
            source_modality="url",
            indicator_type="phishing_url" if result.is_phishing else "url_lexical_analysis",
            description=f"URL evaluated as {result.label.upper()} with {result.phishing_probability * 100:.1f}% phishing probability.",
            supporting_excerpt=url_str,
            severity=severity,
            evidence_source="model_b_phiusiil_classifier",
            confidence=result.confidence,
            observed_versus_inferred="inferred",
            limitations_and_missing_checks=[
                "Lexical pattern analysis only; domain was NOT visited or crawled over HTTP/HTTPS.",
                "Live DNS, WHOIS registration age, and SSL certificate chains not queried.",
            ],
        )
        safe_steps = (
            [
                "Do not enter credentials or passwords on this site.",
                "Inspect the top-level domain and verify against official organization channels.",
                "Report the link to your security team if received unsolicited.",
            ]
            if result.is_phishing
            else [
                "URL exhibits normal lexical patterns.",
                "Verify sender identity if received in an unexpected or urgent message.",
            ]
        )
        explanation = await explanation_service.generate_explanation(
            verdict=verdict,
            score=risk_score,
            tactics=[],
            evidence_items=[url_evidence],
            safe_next_steps=safe_steps,
            untrusted_text=url_str,
            model_signals={"url_classifier": result.model_dump()},
        )

    return URLScanResponse(
        url=url_str,
        is_phishing=result.is_phishing,
        confidence=result.confidence,
        label=result.label,
        phishing_probability=result.phishing_probability,
        risk_score=risk_score,
        severity=severity,
        extracted_features=result.extracted_features,
        threat_indicators=indicators,
        explanation=explanation,
    )


@router.post(
    "/screenshot",
    response_model=ScreenshotAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan Screenshot Image (OCR)",
    description="Accepts PNG or JPEG screenshots, validates magic bytes, extracts text via OCR, passively extracts URLs, and triages threats.",
)
async def scan_screenshot(
    file: UploadFile = File(..., description="Screenshot image file (PNG, JPG, JPEG)"),
) -> ScreenshotAnalysisResponse:
    """Extracts text from screenshot and triages threat vectors."""
    content = await file.read()
    return await ocr_service.process_screenshot(
        file_bytes=content,
        filename=file.filename or "screenshot.png",
        content_type=file.content_type or "image/png",
    )


@router.post(
    "/audio",
    response_model=AudioAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan Audio Message (STT)",
    description="Accepts WAV, MP3, or M4A audio recordings, validates duration, transcribes speech, and analyzes the transcript for scam signals.",
)
async def scan_audio(
    file: UploadFile = File(..., description="Audio recording file (WAV, MP3, M4A, OGG)"),
    x_test_stt_engine: Optional[str] = Header(None, description="Optional override for STT engine during testing"),
) -> AudioAnalysisResponse:
    """Transcribes audio message and triages threat vectors."""
    content = await file.read()
    return await audio_service.process_audio(
        file_bytes=content,
        filename=file.filename or "recording.wav",
        content_type=file.content_type or "audio/wav",
        engine=x_test_stt_engine,
    )


# --- Phase 4: Unified Evidence Fusion & Threat Analysis Endpoints ---

from app.schemas.evidence import (  # noqa: E402
    UnifiedScanRequest,
    UnifiedReportResponse,
)
from app.services.unified_scanner import unified_scanner_service  # noqa: E402
from fastapi import Form  # noqa: E402
from typing import List  # noqa: E402
import json  # noqa: E402


@router.post(
    "/unified",
    response_model=UnifiedReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Unified Multi-Vector Scan (JSON)",
    description=(
        "Fuses text and URL vectors into a unified forensic investigation with normalized evidence items, "
        "evidence-backed manipulation tactics, deterministic risk score, uncalibrated uncertainty disclosures, and safe next steps."
    ),
)
async def scan_unified(payload: UnifiedScanRequest) -> UnifiedReportResponse:
    """Performs unified multi-vector threat investigation via JSON payload."""
    return await unified_scanner_service.investigate(
        text=payload.text,
        urls=payload.urls,
        include_explanation=payload.include_explanation,
    )


@router.post(
    "/investigate",
    response_model=UnifiedReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Multimodal Unified Investigation (Multipart)",
    description=(
        "Accepts optional text, URLs, screenshot image, and audio recording simultaneously. "
        "Extracts OCR text and audio transcripts, correlates signals, deduplicates evidence, and produces a unified threat report."
    ),
)
async def investigate_multimodal(
    text: Optional[str] = Form(None, description="Optional message text or email body"),
    urls: Optional[str] = Form(None, description="Optional URLs as comma-separated or JSON list"),
    screenshot: Optional[UploadFile] = File(None, description="Optional screenshot image file"),
    audio: Optional[UploadFile] = File(None, description="Optional audio recording file"),
    include_explanation: bool = Form(True, description="Whether to include structured threat explanation"),
    x_test_stt_engine: Optional[str] = Header(None, description="Optional override for audio STT engine during testing"),
) -> UnifiedReportResponse:
    """Performs full multimodal investigation across text, URLs, screenshot OCR, and audio STT."""
    parsed_urls: List[str] = []
    if urls:
        raw_urls = urls.strip()
        if raw_urls.startswith("[") and raw_urls.endswith("]"):
            try:
                parsed_urls = json.loads(raw_urls)
            except Exception:
                parsed_urls = [u.strip() for u in raw_urls.strip("[]").split(",") if u.strip()]
        else:
            parsed_urls = [u.strip() for u in raw_urls.split(",") if u.strip()]

    screenshot_bytes = await screenshot.read() if screenshot else None
    audio_bytes = await audio.read() if audio else None

    return await unified_scanner_service.investigate(
        text=text,
        urls=parsed_urls,
        screenshot_bytes=screenshot_bytes,
        screenshot_filename=screenshot.filename if screenshot else None,
        screenshot_content_type=screenshot.content_type if screenshot else None,
        audio_bytes=audio_bytes,
        audio_filename=audio.filename if audio else None,
        audio_content_type=audio.content_type if audio else None,
        audio_stt_engine=x_test_stt_engine,
        include_explanation=include_explanation,
    )
