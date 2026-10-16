"""Typed Machine Learning Inference Engine for PhishLens AI.

Provides strongly-typed prediction methods for:
- Message/SMS spam and suspicious pattern classification (Model A)
- Live lexical URL phishing classification (Model B)
"""
from pathlib import Path
from typing import Dict, Any, Optional
import os
import joblib
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.errors import ModelNotLoadedError, ValidationException
from app.ml.url_extractor import (
    URL_FEATURE_NAMES,
    extract_url_features_dict,
    extract_url_feature_vector,
)


class MessagePredictionResult(BaseModel):
    """Structured result for message classification."""
    text: str = Field(description="Analyzed text input")
    label: str = Field(description="'spam' or 'ham'")
    is_spam: bool = Field(description="True if classified as spam/suspicious")
    confidence: float = Field(description="Confidence score for predicted label (0.0 - 1.0)")
    spam_probability: float = Field(description="Probability of message being spam (0.0 - 1.0)")
    ham_probability: float = Field(description="Probability of message being benign (0.0 - 1.0)")


class URLPredictionResult(BaseModel):
    """Structured result for live URL phishing classification."""
    url: str = Field(description="Analyzed URL input")
    label: str = Field(description="'phishing' or 'legitimate'")
    is_phishing: bool = Field(description="True if classified as phishing")
    confidence: float = Field(description="Confidence score for predicted label (0.0 - 1.0)")
    phishing_probability: float = Field(description="Probability of URL being phishing (0.0 - 1.0)")
    legitimate_probability: float = Field(description="Probability of URL being legitimate (0.0 - 1.0)")
    extracted_features: Dict[str, Any] = Field(
        description="On-the-fly extracted lexical features used for inference"
    )


class InferenceEngine:
    """Thread-safe singleton inference engine managing loaded model artifacts."""

    def __init__(self):
        self._sms_pipeline = None
        self._url_pipeline = None

    def load_models(self) -> None:
        """Attempts to load serialized model pipelines from configured paths."""
        sms_path = Path(settings.SMS_MODEL_PATH)
        if not sms_path.is_absolute() and not sms_path.exists():
            # Try CWD parent, repo root relative to __file__, or backend root
            for candidate in [
                Path.cwd().parent / sms_path,
                Path(__file__).resolve().parents[3] / sms_path,
                Path(__file__).resolve().parents[2] / sms_path,
            ]:
                if candidate.exists():
                    sms_path = candidate
                    break

        if sms_path.exists() and self._sms_pipeline is None:
            try:
                self._sms_pipeline = joblib.load(sms_path)
            except Exception as e:
                print(f"[Warning] Failed loading SMS model from {sms_path}: {e}")

        url_path = Path(settings.URL_MODEL_PATH)
        if not url_path.is_absolute() and not url_path.exists():
            for candidate in [
                Path.cwd().parent / url_path,
                Path(__file__).resolve().parents[3] / url_path,
                Path(__file__).resolve().parents[2] / url_path,
            ]:
                if candidate.exists():
                    url_path = candidate
                    break

        if url_path.exists() and self._url_pipeline is None:
            try:
                self._url_pipeline = joblib.load(url_path)
            except Exception as e:
                print(f"[Warning] Failed loading URL model from {url_path}: {e}")

    @property
    def is_sms_loaded(self) -> bool:
        return self._sms_pipeline is not None

    @property
    def is_url_loaded(self) -> bool:
        return self._url_pipeline is not None

    def predict_message(self, text: str) -> MessagePredictionResult:
        """Performs typed inference on an incoming message string."""
        if not self.is_sms_loaded:
            self.load_models()
        if not self.is_sms_loaded:
            raise ModelNotLoadedError(model_name="sms_classifier")

        cleaned = str(text or "").strip()
        if not cleaned:
            raise ValidationException(
                message="Cannot classify empty message text.",
                details={"input": text},
            )

        # Pipeline expects iterable of strings
        probs = self._sms_pipeline.predict_proba([cleaned])[0]
        # Classes: 0 = ham, 1 = spam
        ham_prob = float(probs[0])
        spam_prob = float(probs[1])

        is_spam = spam_prob >= 0.5
        label = "spam" if is_spam else "ham"
        confidence = spam_prob if is_spam else ham_prob

        return MessagePredictionResult(
            text=cleaned,
            label=label,
            is_spam=is_spam,
            confidence=round(confidence, 4),
            spam_probability=round(spam_prob, 4),
            ham_probability=round(ham_prob, 4),
        )

    def predict_url(self, raw_url: str) -> URLPredictionResult:
        """Performs typed inference on a submitted URL string using on-the-fly lexical features."""
        if not self.is_url_loaded:
            self.load_models()
        if not self.is_url_loaded:
            raise ModelNotLoadedError(model_name="url_classifier")

        cleaned_url = str(raw_url or "").strip()
        if not cleaned_url:
            raise ValidationException(
                message="Cannot classify empty URL string.",
                details={"input": raw_url},
            )

        # Extract live features as DataFrame matching training feature names
        features_dict = extract_url_features_dict(cleaned_url)
        df_features = pd.DataFrame([features_dict], columns=URL_FEATURE_NAMES)

        # Pipeline: StandardScaler -> HistGradientBoostingClassifier
        # Classes: 0 = Legitimate, 1 = Phishing
        probs = self._url_pipeline.predict_proba(df_features)[0]
        legit_prob = float(probs[0])
        phish_prob = float(probs[1])

        is_phish = phish_prob >= 0.5
        label = "phishing" if is_phish else "legitimate"
        confidence = phish_prob if is_phish else legit_prob

        return URLPredictionResult(
            url=cleaned_url,
            label=label,
            is_phishing=is_phish,
            confidence=round(confidence, 4),
            phishing_probability=round(phish_prob, 4),
            legitimate_probability=round(legit_prob, 4),
            extracted_features=features_dict,
        )


inference_engine = InferenceEngine()
