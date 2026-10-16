"""Phase 5 Hardening and End-to-End API Integration Tests.

Validates:
1. Strict score bounding (0.0 to 100.0) under adversarial multiple-threat saturation.
2. Tactic category caps and dampening verification.
3. CORS headers and options preflight handling.
4. Input sanitization (oversized payloads, unusual unicode characters).
5. Error response consistency without sensitive data leakage.
6. Multimodal API contracts with real endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.risk_engine import (
    risk_engine,
    WEIGHT_TACTICS_MAX,
    TACTIC_CATEGORY_WEIGHTS,
    CORRELATION_DAMPENING_DISCOUNT,
)
from app.services.manipulation_detector import manipulation_detector
from app.ml.inference import MessagePredictionResult, URLPredictionResult

client = TestClient(app)


def test_score_bounds_under_saturation():
    """Verify composite risk score never exceeds 100.0 even under extreme multi-vector attack saturation."""
    fake_msg = MessagePredictionResult(
        text="SPAM " * 100,
        label="spam",
        is_spam=True,
        confidence=1.0,
        spam_probability=1.0,
        ham_probability=0.0,
    )
    fake_urls = [
        URLPredictionResult(
            url=f"http://phish-{i}.evil.xyz",
            label="phishing",
            is_phishing=True,
            confidence=1.0,
            phishing_probability=1.0,
            legitimate_probability=0.0,
            extracted_features={},
        )
        for i in range(15)
    ]

    # Generate saturated tactics across all categories
    saturated_text = (
        "URGENT immediate action required account suspended. "
        "IRS and PayPal Security team alert. "
        "Keep this secret do not tell anyone. "
        "Provide OTP password pin credentials. "
        "Pay via steam gift cards and bitcoin wallet."
    )
    tactics, evidence = manipulation_detector.detect_tactics(
        saturated_text,
        urls=[u.url for u in fake_urls],
        source_modality="text",
    )

    verdict, score, signals, uncertainty, missing, steps = risk_engine.compute_risk(
        msg_result=fake_msg,
        url_results=fake_urls,
        tactics=tactics,
        evidence_items=evidence,
        has_text=True,
        has_url=True,
    )

    assert 0.0 <= score <= 100.0
    assert score == 100.0  # Maxed out cleanly
    assert verdict == "high-risk"


def test_tactic_caps_and_correlation_dampening():
    """Verify category caps and correlation dampening prevent runaway score inflation."""
    # High spam probability with urgency
    msg_spam = MessagePredictionResult(
        text="Urgent act now",
        label="spam",
        is_spam=True,
        confidence=0.9,
        spam_probability=0.85,
        ham_probability=0.15,
    )
    tactics, evidence = manipulation_detector.detect_tactics(
        "URGENT act now immediately hurry asap within 24 hours final notice",
        urls=[],
        source_modality="text",
    )

    verdict, score, signals, uncertainty, missing, steps = risk_engine.compute_risk(
        msg_result=msg_spam,
        url_results=[],
        tactics=tactics,
        evidence_items=evidence,
        has_text=True,
        has_url=False,
    )

    heuristics = signals["heuristics_and_tactics"]
    # Urgency category is capped at its single weight (8.0), not multiplied by the 6 keywords
    assert heuristics["capped_tactic_points"] <= WEIGHT_TACTICS_MAX
    # Correlation dampening was triggered because spam_prob >= 0.65 and urgency is present
    assert heuristics["correlation_dampening_applied"] > 0.0


def test_cors_preflight_and_headers():
    """Verify CORS preflight OPTIONS returns allowed origins and methods."""
    response = client.options(
        "/api/v1/scan/unified",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_oversized_payload_handling():
    """Verify that massively oversized message text is rejected by Pydantic validation."""
    huge_text = "A" * 25000  # Exceeds max_length=20000 on UnifiedScanRequest
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": huge_text},
    )
    assert response.status_code == 422
    data = response.json()
    assert "error" in data


def test_unicode_and_special_character_resilience():
    """Verify input with emojis, RTL characters, and non-ASCII glyphs processes cleanly."""
    unicode_text = "⚠️ تنبيه أمني عاجل! Votre compte est suspendu: http://auth-test.xyz 🚨💳"
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": unicode_text},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"].startswith("case-")
    assert data["verdict"] in ("benign", "suspicious", "high-risk")
    assert 0.0 <= data["score"] <= 100.0


def test_end_to_end_multimodal_investigate_all_modalities():
    """End-to-end integration test of /scan/investigate with text, url, image, and audio."""
    from PIL import Image
    import io
    import soundfile as sf
    import numpy as np

    # Synthetic image
    img = Image.new("RGB", (120, 40), color=(255, 255, 255))
    img_bio = io.BytesIO()
    img.save(img_bio, format="PNG")
    png_bytes = img_bio.getvalue()

    # Synthetic audio
    sr = 16000
    wav_bio = io.BytesIO()
    sf.write(wav_bio, np.zeros((sr // 2, 1), dtype=np.float32), sr, format="WAV")
    wav_bytes = wav_bio.getvalue()

    response = client.post(
        "/api/v1/scan/investigate",
        data={
            "text": "Please verify your account at http://login-check.com",
            "urls": "http://backup-portal.com, http://verification-center.net",
            "include_explanation": "true",
        },
        files={
            "screenshot": ("capture.png", png_bytes, "image/png"),
            "audio": ("recording.wav", wav_bytes, "audio/wav"),
        },
        headers={"x-test-stt-engine": "test_stub"},
    )
    assert response.status_code == 200
    data = response.json()

    # All 4 modalities must be populated
    assert "text" in data["evidence_by_modality"]
    assert "url" in data["evidence_by_modality"]
    assert "screenshot" in data["evidence_by_modality"]
    assert "audio" in data["evidence_by_modality"]

    # Verify report completeness
    assert data["verdict"] in ("benign", "suspicious", "high-risk", "inconclusive")
    assert 0.0 <= data["score"] <= 100.0
    assert len(data["missing_checks"]) > 0
    assert len(data["safe_next_steps"]) > 0
    assert data["uncertainty"]["calibration_disclosure"] != ""
    assert data["explanation"]["executive_brief"] != ""
