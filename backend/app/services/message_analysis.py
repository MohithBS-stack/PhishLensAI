"""Unified Message and Threat Analysis Service for PhishLens AI.

Reused across text inputs, screenshot OCR text, and transcribed audio.
Performs:
1. URL extraction (passive, strictly non-visiting).
2. URL phishing analysis via Model B.
3. Text spam/suspicious classification via Model A.
4. Threat indicator extraction (urgency, credential harvesting, financial lures).
5. Composite risk scoring and severity ranking.
"""
from typing import List, Tuple, Dict, Any
import re
from app.ml.inference import inference_engine
from app.schemas.scan import (
    MessageAnalysisReport,
    ThreatIndicator,
    URLScanSummary,
)

# Common urgency and phishing indicator keyword patterns
URGENCY_PATTERNS = [
    (r"\b(urgent|immediately|immediate action|act now|hurry|asap|within 24 hours)\b", "Urgency Trigger", "high", "Pressures the recipient to act impulsively without verifying legitimacy"),
    (r"\b(suspended|terminated|deactivated|restricted|frozen|locked out|security alert)\b", "Account Suspension Scare", "high", "Fabricates critical account status changes to elicit panic"),
    (r"\b(verify your account|confirm your identity|update billing|login to verify|claim prize)\b", "Credential / Identity Lure", "high", "Solicits sensitive credentials, payment details, or personal information"),
    (r"\b(winner|lottery|won \$?\d+|cash prize|free gift|gift card|refund|unclaimed funds)\b", "Financial / Prize Lure", "medium", "Promises unsolicited monetary rewards or gift cards typical of scam operations"),
    (r"\b(bitcoin|crypto|usdt|eth|wire transfer|western union|cashapp|venmo)\b", "Irreversible Payment Cue", "medium", "Mentions irreversible payment rails frequently abused in financial fraud"),
]

# URL extraction regex (captures http, https, and www domain links)
URL_REGEX = re.compile(
    r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
)


class MessageAnalysisService:
    """Service providing unified message threat analysis."""

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Passively extracts URL-like strings from text without visiting or resolving them."""
        if not text:
            return []
        matches = URL_REGEX.findall(text)
        urls: List[str] = []
        for match in matches:
            url_str = match[0] if isinstance(match, tuple) else match
            url_str = url_str.strip().rstrip(".,;!?:")
            if url_str and url_str not in urls:
                urls.append(url_str)
        return urls

    @classmethod
    def analyze_message(cls, text: str) -> MessageAnalysisReport:
        """Evaluates text, extracts URLs passively, scores threat vectors, and computes composite risk."""
        cleaned_text = str(text or "").strip()
        indicators: List[ThreatIndicator] = []
        url_summaries: List[URLScanSummary] = []

        if not cleaned_text:
            return MessageAnalysisReport(
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

        # 1. Message Classification via Model A
        msg_result = inference_engine.predict_message(cleaned_text)

        # 2. Passive URL Extraction & Evaluation via Model B
        extracted_urls = cls.extract_urls(cleaned_text)
        any_phishing_url = False

        for url in extracted_urls:
            url_result = inference_engine.predict_url(url)
            if url_result.is_phishing:
                any_phishing_url = True
                indicators.append(
                    ThreatIndicator(
                        indicator_type="phishing_url",
                        name="Phishing URL Detected",
                        severity="critical",
                        description=f"Extracted URL exhibited structural characteristics of phishing ({url_result.confidence * 100:.1f}% confidence)",
                        evidence=url,
                    )
                )
            url_summaries.append(
                URLScanSummary(
                    url=url,
                    is_phishing=url_result.is_phishing,
                    confidence=url_result.confidence,
                    label=url_result.label,
                    phishing_probability=url_result.phishing_probability,
                    extracted_features=url_result.extracted_features,
                )
            )

        # 3. Urgency and Threat Keyword Scanning
        for pattern, name, sev, desc in URGENCY_PATTERNS:
            match = re.search(pattern, cleaned_text, re.IGNORECASE)
            if match:
                indicators.append(
                    ThreatIndicator(
                        indicator_type="heuristic_keyword",
                        name=name,
                        severity=sev,
                        description=desc,
                        evidence=match.group(0),
                    )
                )

        if msg_result.is_spam:
            indicators.append(
                ThreatIndicator(
                    indicator_type="ml_spam_classifier",
                    name="Spam/Smishing Language Pattern",
                    severity="high" if msg_result.spam_probability > 0.85 else "medium",
                    description=f"Message body classified as spam with {msg_result.spam_probability * 100:.1f}% probability",
                    evidence=None,
                )
            )

        # 4. Composite Risk Score Calculation (0.0 to 100.0)
        base_score = msg_result.spam_probability * 60.0

        if any_phishing_url:
            base_score = max(base_score, 85.0) + 15.0
        elif extracted_urls:
            base_score += 10.0

        heuristic_bonus = min(len(indicators) * 8.0, 25.0)
        risk_score = min(max(round(base_score + heuristic_bonus, 1), 0.0), 100.0)

        # 5. Severity Categorization
        if risk_score >= 80.0 or any_phishing_url:
            severity = "critical"
        elif risk_score >= 55.0:
            severity = "high"
        elif risk_score >= 30.0:
            severity = "medium"
        else:
            severity = "low"

        is_suspicious = (risk_score >= 40.0) or msg_result.is_spam or any_phishing_url

        return MessageAnalysisReport(
            text=cleaned_text,
            label=msg_result.label,
            is_suspicious=is_suspicious,
            confidence=msg_result.confidence,
            risk_score=risk_score,
            severity=severity,
            threat_indicators=indicators,
            extracted_urls=extracted_urls,
            url_evaluations=url_summaries,
        )


message_analysis_service = MessageAnalysisService()
