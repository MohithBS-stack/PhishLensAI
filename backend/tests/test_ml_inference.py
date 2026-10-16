"""Tests for Phase 2 ML feature extraction and inference engine."""
import pytest
from app.ml.url_extractor import (
    URL_FEATURE_NAMES,
    extract_url_features_dict,
    extract_url_feature_vector,
)
from app.ml.inference import inference_engine
from app.services.model_registry import model_registry
from app.core.errors import ValidationException


def test_url_feature_extractor_structure():
    """Verify URL feature extractor outputs all 18 features with expected keys."""
    sample_url = "https://secure-bank.example.com/login?token=abc%20123"
    feats = extract_url_features_dict(sample_url)

    assert isinstance(feats, dict)
    assert len(feats) == 18
    for name in URL_FEATURE_NAMES:
        assert name in feats

    assert feats["IsHTTPS"] == 1
    assert feats["NoOfSubDomain"] >= 1
    assert feats["HasObfuscation"] == 1  # '%20'
    assert feats["NoOfObfuscatedChar"] == 3
    assert feats["NoOfEqualsInURL"] == 1
    assert feats["NoOfQMarkInURL"] == 1


def test_url_feature_extractor_ip_detection():
    """Verify IP detection in URL domain."""
    ip_url = "http://192.168.1.100/admin/panel"
    feats = extract_url_features_dict(ip_url)
    assert feats["IsDomainIP"] == 1
    assert feats["IsHTTPS"] == 0

    vec = extract_url_feature_vector(ip_url)
    assert len(vec) == 18


def test_model_registry_loaded_status():
    """Verify both trained models are loaded and reported in registry status."""
    inference_engine.load_models()
    assert inference_engine.is_sms_loaded is True
    assert inference_engine.is_url_loaded is True

    status = model_registry.get_status()
    assert status["sms_classifier"] is True
    assert status["url_classifier"] is True


def test_message_classifier_inference():
    """Verify Model A predicts spam and ham messages accurately."""
    inference_engine.load_models()

    # Clear spam sample
    spam_sample = "FREE PRIZE! You have won a $1,000 Walmart Gift Card! Call 0800-123-456 immediately to claim now!"
    spam_result = inference_engine.predict_message(spam_sample)
    assert spam_result.is_spam is True
    assert spam_result.label == "spam"
    assert spam_result.spam_probability > 0.70
    assert 0.0 <= spam_result.confidence <= 1.0

    # Clear benign sample
    ham_sample = "Hey, are we still meeting for lunch at the cafeteria around 12:30?"
    ham_result = inference_engine.predict_message(ham_sample)
    assert ham_result.is_spam is False
    assert ham_result.label == "ham"
    assert ham_result.ham_probability > 0.70
    assert 0.0 <= ham_result.confidence <= 1.0


def test_message_classifier_validation_error():
    """Verify empty text raises ValidationException."""
    with pytest.raises(ValidationException):
        inference_engine.predict_message("   ")


def test_url_classifier_inference():
    """Verify Model B predicts phishing and legitimate URLs accurately."""
    inference_engine.load_models()

    # Suspicious phishing-like pattern with IP and obfuscation
    phish_sample = "http://att-103731-107123.weeblysite.com/login.php?user=admin&id=%20"
    phish_result = inference_engine.predict_url(phish_sample)
    assert phish_result.is_phishing is True
    assert phish_result.label == "phishing"
    assert phish_result.phishing_probability > 0.70
    assert "URLLength" in phish_result.extracted_features

    # Legitimate standard HTTPS site
    legit_sample = "https://www.southbankmosaics.com"
    legit_result = inference_engine.predict_url(legit_sample)
    assert legit_result.is_phishing is False
    assert legit_result.label == "legitimate"
    assert legit_result.legitimate_probability > 0.70


def test_url_classifier_validation_error():
    """Verify empty URL raises ValidationException."""
    with pytest.raises(ValidationException):
        inference_engine.predict_url("")
