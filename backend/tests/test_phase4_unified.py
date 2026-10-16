"""Comprehensive Unit and Integration Tests for Phase 4: Unified Evidence Fusion & Threat Analysis.

Validates:
1. Benign cases (conversational ham text, legitimate URLs).
2. Phishing indicators (urgency, authority impersonation, secrecy, credential lure, gift card payments).
3. Conflicting signals (benign text + phishing URL, spam text + legitimate URL).
4. Duplicate evidence deduplication across modalities and repetitions.
5. Missing modalities handling and missing check tracking.
6. Empty or sparse input handling resulting in 'inconclusive' verdict.
7. LLM explanation provider failures, timeouts, and malformed outputs fallback.
8. Multimodal multipart investigation endpoint (/scan/investigate).
"""
import io
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.manipulation_detector import manipulation_detector
from app.services.risk_engine import risk_engine
from app.services.explanation_service import explanation_service
from app.services.unified_scanner import unified_scanner_service
from app.schemas.evidence import (
    UnifiedScanRequest,
    UnifiedReportResponse,
    NormalizedEvidence,
    ManipulationTactic,
)

client = TestClient(app)


# --- 1. Benign Cases ---

def test_unified_benign_text():
    """Validates that normal conversational text is scored as benign with low uncertainty."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": "Hey Sarah, let me know what time we are meeting for coffee tomorrow morning."}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "benign"
    assert data["score"] < 30.0
    assert len(data["manipulation_tactics"]) == 0
    assert data["explanation"]["is_llm_generated"] is False
    assert "BENIGN" in data["explanation"]["summary"]


def test_unified_benign_url():
    """Validates that a legitimate, high-reputation URL is classified as benign."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"urls": ["https://www.southbankmosaics.com"]}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "benign"
    assert data["score"] < 30.0
    assert len(data["evidence_by_modality"]["url"]) >= 1


# --- 2. Phishing & Manipulation Indicators ---

def test_unified_phishing_urgency_and_fake_authority():
    """Validates urgency deadlines, authority claims, and phishing URLs yield high-risk verdict."""
    response = client.post(
        "/api/v1/scan/unified",
        json={
            "text": "URGENT: PayPal Security Team Alert. Your account will be suspended within 24 hours. Log in to verify your identity at http://paypal-security-update.xyz"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high-risk"
    assert data["score"] >= 70.0

    categories = [t["category"] for t in data["manipulation_tactics"]]
    assert "urgency" in categories
    assert "authority_impersonation" in categories
    assert "identity_inconsistency" in categories

    # Verify supporting excerpts exist
    assert any("24 hours" in s or "urgent" in s.lower() for s in data["supporting_excerpts"])
    assert len(data["safe_next_steps"]) >= 3


def test_unified_credential_and_otp_harvesting():
    """Validates explicit credential and OTP requests trigger critical severity tactics."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": "Security Alert: Please enter your password and provide your one-time code OTP immediately."}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["score"] >= 30.0

    cred_tactics = [t for t in data["manipulation_tactics"] if t["category"] == "credential_request"]
    assert len(cred_tactics) >= 1
    assert cred_tactics[0]["severity"] in ("high", "critical")
    assert "OTP" in cred_tactics[0]["supporting_evidence"] or "password" in cred_tactics[0]["supporting_evidence"]


def test_unified_secrecy_and_giftcard_payment():
    """Validates secrecy demands and gift card requests are detected and categorized."""
    response = client.post(
        "/api/v1/scan/unified",
        json={
            "text": "Do not tell anyone or contact your bank. You must buy Steam gift cards and pay the clearance fee right away."
        }
    )
    assert response.status_code == 200
    data = response.json()
    categories = [t["category"] for t in data["manipulation_tactics"]]
    assert "secrecy" in categories
    assert "payment_request" in categories


# --- 3. Conflicting Signals ---

def test_unified_conflicting_signals_benign_text_phishing_url():
    """Validates that benign text paired with a phishing URL flags conflicting signals and elevates risk."""
    response = client.post(
        "/api/v1/scan/unified",
        json={
            "text": "Hi friend, here are the vacation photos from our weekend trip.",
            "urls": ["http://chase-bank-verify-account.tk"]
        }
    )
    assert response.status_code == 200
    data = response.json()
    # The URL is suspicious/phishing, so risk should be elevated
    assert data["verdict"] in ("suspicious", "high-risk")
    # Conflict signal should be recorded in uncertainty
    conflicts = data["uncertainty"]["conflicting_signals"]
    assert any("benign" in c.lower() or "malicious" in c.lower() or "phishing" in c.lower() for c in conflicts)


def test_unified_conflicting_signals_spam_text_clean_url():
    """Validates spam text paired with clean legitimate URL detects the discrepancy."""
    response = client.post(
        "/api/v1/scan/unified",
        json={
            "text": "CONGRATULATIONS! You won a $1000 Walmart Gift Card! Claim your cash prize now!",
            "urls": ["https://www.google.com"]
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["score"] >= 30.0
    conflicts = data["uncertainty"]["conflicting_signals"]
    assert any("spam" in c.lower() or "legitimate" in c.lower() for c in conflicts)


# --- 4. Duplicate Evidence Deduplication ---

def test_unified_duplicate_evidence_deduplication():
    """Validates that repeated occurrences of identical keywords do not blow up score repeatedly."""
    single_res = client.post(
        "/api/v1/scan/unified",
        json={"text": "URGENT: Act now immediately."}
    )
    repeated_res = client.post(
        "/api/v1/scan/unified",
        json={"text": "URGENT URGENT URGENT: Act now immediately act now immediately hurry hurry."}
    )
    assert single_res.status_code == 200
    assert repeated_res.status_code == 200

    single_data = single_res.json()
    repeated_data = repeated_res.json()

    # The category cap and correlation dampening should prevent score from skyrocketing
    assert repeated_data["score"] <= single_data["score"] + 15.0

    # Check evidence deduplication
    evidence_ids = [e["evidence_id"] for e in repeated_data["all_evidence"]]
    assert len(evidence_ids) == len(set(evidence_ids))


# --- 5. Missing Modalities Handling ---

def test_unified_missing_modalities_text_only():
    """Validates missing checks are explicitly noted when only text is provided."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": "Routine notice regarding your team calendar invite."}
    )
    assert response.status_code == 200
    data = response.json()
    missing = data["missing_checks"]
    assert any("No URL" in m or "URL" in m for m in missing)
    assert any("screenshot" in m.lower() for m in missing)
    assert any("audio" in m.lower() for m in missing)


def test_unified_missing_modalities_url_only():
    """Validates missing checks are explicitly noted when only URLs are provided."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"urls": ["https://docs.python.org/3/"]}
    )
    assert response.status_code == 200
    data = response.json()
    missing = data["missing_checks"]
    assert any("screenshot" in m.lower() for m in missing)
    assert any("audio" in m.lower() for m in missing)


# --- 6. Empty Input Handling ---

def test_unified_empty_input():
    """Validates completely empty input returns inconclusive verdict with high uncertainty."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": None, "urls": None}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "inconclusive"
    assert data["score"] == 0.0
    assert data["uncertainty"]["is_uncertain"] is True
    assert data["uncertainty"]["uncertainty_level"] == "high"


def test_unified_blank_spaces_input():
    """Validates whitespace-only text returns inconclusive verdict."""
    response = client.post(
        "/api/v1/scan/unified",
        json={"text": "     "}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "inconclusive"
    assert data["score"] == 0.0


# --- 7. LLM Provider Failures & Malformed Outputs (Mocked) ---

@pytest.mark.asyncio
async def test_explanation_fallback_when_no_api_key():
    """Validates deterministic fallback generator is used when no API key is available."""
    explanation = await explanation_service.generate_explanation(
        verdict="high-risk",
        score=85.0,
        tactics=[
            ManipulationTactic(
                tactic_id="t1",
                category="urgency",
                name="Urgency & Immediate Action Trigger",
                description="Pressures recipient",
                severity="high",
                supporting_evidence="within 24 hours",
            )
        ],
        evidence_items=[],
        safe_next_steps=["Do not click links"],
        untrusted_text="Suspicious text payload",
    )
    assert explanation.is_llm_generated is False
    assert explanation.model_name == "Deterministic Rule-Grounded Generator"
    assert "HIGH-RISK" in explanation.summary
    assert len(explanation.key_concerns) >= 1
    assert len(explanation.remediation_advice) >= 1


@pytest.mark.asyncio
async def test_explanation_fallback_on_mock_llm_exception():
    """Validates graceful fallback when LLM API raises a connection or timeout error."""
    with patch("os.getenv", return_value="fake-api-key"):
        with patch.object(explanation_service, "_call_gemini_llm", side_effect=RuntimeError("Google GenAI Connection Timeout")):
            explanation = await explanation_service.generate_explanation(
                verdict="suspicious",
                score=55.0,
                tactics=[],
                evidence_items=[],
                safe_next_steps=["Verify with sender"],
                untrusted_text="Suspicious text",
            )
            assert explanation.is_llm_generated is False
            assert "SUSPICIOUS" in explanation.summary


@pytest.mark.asyncio
async def test_explanation_fallback_on_malformed_llm_output():
    """Validates handling of malformed or non-JSON responses from LLM."""
    mock_response = MagicMock()
    mock_response.text = "NOT JSON: <malformed XML and text>"

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("os.getenv", return_value="fake-api-key"):
        with patch("google.genai.Client", return_value=mock_client):
            explanation = await explanation_service.generate_explanation(
                verdict="suspicious",
                score=45.0,
                tactics=[],
                evidence_items=[],
                safe_next_steps=["Check sender"],
                untrusted_text="Test message",
            )
            # JSON parsing error causes graceful fallback to deterministic generator
            assert explanation.is_llm_generated is False
            assert explanation.model_name == "Deterministic Rule-Grounded Generator"


# --- 8. Multipart Multimodal Investigation Endpoint (/scan/investigate) ---

def test_investigate_multimodal_multipart_text_and_url():
    """Validates /scan/investigate endpoint with form text and URL string."""
    response = client.post(
        "/api/v1/scan/investigate",
        data={
            "text": "Urgent alert: Account suspended.",
            "urls": "http://secure-login-chase.xyz",
            "include_explanation": "true",
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"].startswith("case-")
    assert data["verdict"] in ("suspicious", "high-risk")
    assert len(data["all_evidence"]) >= 1


def test_investigate_multimodal_multipart_with_audio_and_image():
    """Validates full multimodal investigation with synthetic image and audio."""
    from PIL import Image
    img = Image.new("RGB", (100, 100), color=(255, 255, 255))
    png_bio = io.BytesIO()
    img.save(png_bio, format="PNG")
    png_bytes = png_bio.getvalue()

    # Synthetic 0.5s mono WAV
    import numpy as np
    import soundfile as sf
    sample_rate = 16000
    sine_wave = (np.sin(2 * np.pi * 440 * np.linspace(0, 0.5, int(sample_rate * 0.5))) * 32767).astype(np.int16)
    wav_bio = io.BytesIO()
    sf.write(wav_bio, sine_wave, sample_rate, format="WAV", subtype="PCM_16")
    wav_bytes = wav_bio.getvalue()

    response = client.post(
        "/api/v1/scan/investigate",
        data={"text": "Review attached evidence"},
        files={
            "screenshot": ("sample.png", png_bytes, "image/png"),
            "audio": ("voice.wav", wav_bytes, "audio/wav"),
        },
        headers={"x-test-stt-engine": "test_stub"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["case_id"].startswith("case-")
    assert "screenshot" in data["evidence_by_modality"]
    assert "audio" in data["evidence_by_modality"]
    assert len(data["evidence_by_modality"]["screenshot"]) >= 1
    assert len(data["evidence_by_modality"]["audio"]) >= 1
    assert data["uncertainty"]["calibration_disclosure"] != ""
