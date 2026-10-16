"""Multimodal scanning and threat analysis API endpoints."""
from fastapi import APIRouter, File, UploadFile, status, Header
from typing import Optional

from app.schemas.scan import (
    TextScanRequest,
    MessageAnalysisReport,
    ScreenshotAnalysisResponse,
    AudioAnalysisResponse,
)
from app.services.message_analysis import message_analysis_service
from app.services.ocr_service import ocr_service
from app.services.audio_service import audio_service

router = APIRouter(prefix="/scan", tags=["Scanning & Threat Analysis"])


@router.post(
    "/text",
    response_model=MessageAnalysisReport,
    status_code=status.HTTP_200_OK,
    summary="Scan Message / SMS Text",
    description="Analyzes message text for spam/smishing patterns, passively extracts embedded URLs, and scores overall threat severity.",
)
async def scan_text(payload: TextScanRequest) -> MessageAnalysisReport:
    """Performs unified text threat analysis."""
    return message_analysis_service.analyze_message(payload.text)


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
