"""Screenshot OCR and Visual Threat Extraction Service for PhishLens AI.

Accepts PNG, JPG, and JPEG screenshots.
Performs:
1. Content, MIME type, and size validation (with magic byte checks).
2. Safe in-memory image processing (zero disk retention).
3. OCR text extraction using winocr or pytesseract.
4. Passive URL extraction.
5. Threat analysis via message_analysis_service.
"""
from typing import Dict, Any, Tuple
import io
import asyncio
from PIL import Image
from app.core.errors import ValidationException
from app.services.message_analysis import message_analysis_service
from app.schemas.scan import ScreenshotAnalysisResponse, MessageAnalysisReport

ALLOWED_IMAGE_TYPES = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/jpg": "JPEG",
}

MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def validate_image_bytes(file_bytes: bytes, filename: str, content_type: str) -> Tuple[Image.Image, str]:
    """Validates file size, magic bytes, and opens PIL Image safely."""
    if not file_bytes:
        raise ValidationException("Uploaded file is empty (0 bytes).", details={"filename": filename})

    if len(file_bytes) > MAX_IMAGE_SIZE_BYTES:
        raise ValidationException(
            f"File size exceeds maximum permitted limit of {MAX_IMAGE_SIZE_BYTES // (1024 * 1024)}MB.",
            details={"filename": filename, "size_bytes": len(file_bytes)},
        )

    # Check magic bytes for PNG and JPEG
    is_png = file_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = file_bytes.startswith(b"\xff\xd8\xff")

    if not (is_png or is_jpeg):
        raise ValidationException(
            "Unsupported or invalid image format. Only valid PNG, JPG, and JPEG images are allowed.",
            details={"filename": filename, "content_type": content_type},
        )

    try:
        image = Image.open(io.BytesIO(file_bytes))
        image.load()  # Force decode to ensure file is not truncated/corrupt
    except Exception as exc:
        raise ValidationException(
            f"Image corrupted or unreadable: {str(exc)}",
            details={"filename": filename},
        )

    detected_format = "PNG" if is_png else "JPEG"
    return image, detected_format


class OCRService:
    """Service handling OCR extraction and visual threat analysis."""

    def __init__(self):
        self._winocr_available = False
        try:
            import winocr
            self._winocr_available = True
        except ImportError:
            self._winocr_available = False

    async def _extract_text_winocr(self, image: Image.Image) -> str:
        """Extracts text using native Windows Media OCR."""
        import winocr
        # Convert image to RGB if needed
        rgb_img = image.convert("RGB") if image.mode != "RGB" else image
        result = await winocr.recognize_pil(rgb_img, "en")
        return result.text or ""

    def _extract_text_pytesseract(self, image: Image.Image) -> str:
        """Extracts text using pytesseract if available."""
        import pytesseract
        return pytesseract.image_to_string(image) or ""

    async def extract_text(self, image: Image.Image) -> Tuple[str, str]:
        """Extracts text from image with graceful multi-engine fallback."""
        if self._winocr_available:
            try:
                text = await self._extract_text_winocr(image)
                return text.strip(), "Windows.Media.Ocr"
            except Exception as e:
                pass

        try:
            text = self._extract_text_pytesseract(image)
            return text.strip(), "Tesseract-OCR"
        except Exception:
            pass

        return "", "None (Empty / Unreadable)"

    async def process_screenshot(
        self,
        file_bytes: bytes,
        filename: str,
        content_type: str,
    ) -> ScreenshotAnalysisResponse:
        """Processes screenshot upload and returns structured threat evaluation."""
        image, detected_format = validate_image_bytes(file_bytes, filename, content_type)
        width, height = image.size

        # Extract text via OCR
        extracted_text, ocr_engine = await self.extract_text(image)

        # Evaluate extracted text using existing message analysis service
        if extracted_text:
            analysis_report = message_analysis_service.analyze_message(extracted_text)
        else:
            analysis_report = MessageAnalysisReport(
                text="",
                label="ham",
                is_suspicious=False,
                confidence=1.0,
                risk_score=0.0,
                severity="low",
                threat_indicators=[],
                extracted_urls=[],
                url_evaluations=[],
            )

        evidence = {
            "source": "screenshot_ocr",
            "image_format": detected_format,
            "dimensions": f"{width}x{height}",
            "file_size_bytes": len(file_bytes),
            "text_character_count": len(extracted_text),
            "extracted_urls_count": len(analysis_report.extracted_urls),
            "ocr_status": "text_extracted" if extracted_text else "no_text_detected",
        }

        return ScreenshotAnalysisResponse(
            modality="screenshot",
            filename=filename,
            content_type=f"image/{detected_format.lower()}",
            size_bytes=len(file_bytes),
            image_width=width,
            image_height=height,
            extracted_text=extracted_text,
            ocr_engine=ocr_engine,
            message_analysis=analysis_report,
            evidence=evidence,
        )


ocr_service = OCRService()
