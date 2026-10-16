"""Unit tests for Phase 3 Multimodal Analysis: Screenshot OCR and Audio Transcription."""
import io
import pytest
import numpy as np
import soundfile as sf
from PIL import Image, ImageDraw
from fastapi import status


@pytest.fixture
def synthetic_png_bytes():
    """Generates small valid in-memory PNG image."""
    img = Image.new("RGB", (300, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 30), "Urgent: Verify account at http://login-secure-bank.com", fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def synthetic_blank_png_bytes():
    """Generates small blank in-memory PNG image."""
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def synthetic_wav_bytes():
    """Generates small valid in-memory 1-second WAV audio."""
    samplerate = 16000
    # 1 second of silence / tone
    audio_data = np.zeros((samplerate, 1), dtype=np.float32)
    buf = io.BytesIO()
    sf.write(buf, audio_data, samplerate, format="WAV")
    return buf.getvalue()


def test_text_scan_endpoint_clean(client):
    """Verify POST /api/v1/scan/text returns low risk for benign message."""
    response = client.post(
        "/api/v1/scan/text",
        json={"text": "Hey Sarah, are we still meeting for lunch at 1pm?"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["label"] == "ham"
    assert data["is_suspicious"] is False
    assert data["severity"] in ("low", "medium")
    assert len(data["extracted_urls"]) == 0


def test_text_scan_endpoint_suspicious_with_url(client):
    """Verify POST /api/v1/scan/text detects urgency and extracts URLs."""
    response = client.post(
        "/api/v1/scan/text",
        json={
            "text": "URGENT: Your bank account is suspended! Verify immediately at http://att-103731-107123.weeblysite.com/login.php?user=admin&id=%20"
        },
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_suspicious"] is True
    assert data["severity"] in ("high", "critical")
    assert len(data["extracted_urls"]) >= 1
    assert len(data["threat_indicators"]) >= 1


def test_screenshot_scan_success(client, synthetic_png_bytes):
    """Verify POST /api/v1/scan/screenshot accepts valid PNG and returns structured response."""
    response = client.post(
        "/api/v1/scan/screenshot",
        files={"file": ("screenshot.png", synthetic_png_bytes, "image/png")},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["modality"] == "screenshot"
    assert data["filename"] == "screenshot.png"
    assert data["content_type"] == "image/png"
    assert data["image_width"] == 300
    assert data["image_height"] == 100
    assert "ocr_engine" in data
    assert "message_analysis" in data
    assert "evidence" in data
    assert data["evidence"]["source"] == "screenshot_ocr"


def test_screenshot_scan_blank_image(client, synthetic_blank_png_bytes):
    """Verify blank screenshot is handled gracefully without crashing."""
    response = client.post(
        "/api/v1/scan/screenshot",
        files={"file": ("blank.png", synthetic_blank_png_bytes, "image/png")},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["modality"] == "screenshot"
    assert data["message_analysis"]["is_suspicious"] is False
    assert data["message_analysis"]["severity"] == "low"


def test_screenshot_scan_invalid_format(client):
    """Verify non-image upload returns 422 validation error."""
    fake_bytes = b"This is a text file masquerading as image"
    response = client.post(
        "/api/v1/scan/screenshot",
        files={"file": ("test.png", fake_bytes, "image/png")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_screenshot_scan_empty_file(client):
    """Verify empty 0-byte file returns 422 validation error."""
    response = client.post(
        "/api/v1/scan/screenshot",
        files={"file": ("empty.png", b"", "image/png")},
    )
    assert response.status_code == 422


def test_audio_scan_success(client, synthetic_wav_bytes):
    """Verify POST /api/v1/scan/audio accepts valid WAV and returns transcription report."""
    response = client.post(
        "/api/v1/scan/audio",
        files={"file": ("test_voicemail.wav", synthetic_wav_bytes, "audio/wav")},
        headers={"x-test-stt-engine": "test_stub"},
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["modality"] == "audio"
    assert data["filename"] == "test_voicemail.wav"
    assert data["duration_seconds"] == 1.0
    assert data["sample_rate"] == 16000
    assert data["channels"] == 1
    assert "transcript" in data
    assert "message_analysis" in data
    assert "evidence" in data
    assert data["evidence"]["source"] == "audio_transcription"

    # Verify voice-cloning disclaimer is present
    assert "disclaimer" in data
    assert "synthetic voices" in data["disclaimer"]


def test_audio_scan_invalid_file(client):
    """Verify invalid audio bytes returns 422 validation error."""
    bad_bytes = b"Corrupted invalid audio data"
    response = client.post(
        "/api/v1/scan/audio",
        files={"file": ("corrupt.wav", bad_bytes, "audio/wav")},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_audio_scan_empty_file(client):
    """Verify empty audio file returns 422 validation error."""
    response = client.post(
        "/api/v1/scan/audio",
        files={"file": ("empty.wav", b"", "audio/wav")},
    )
    assert response.status_code == 422
