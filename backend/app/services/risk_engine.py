"""Deterministic, Configurable Threat Scoring & Risk Engine for PhishLens AI.

Principles:
1. Completely deterministic and reproducible.
2. Documented scoring weights, thresholds, and correlation dampening.
3. Explicit missing evidence tracking and uncalibrated probability disclosure.
4. LLM outputs never determine the risk score.
5. Supported verdicts: 'benign', 'suspicious', 'high-risk', 'inconclusive'.
"""
from typing import List, Dict, Any, Optional, Tuple
from app.core.config import settings
from app.ml.inference import MessagePredictionResult, URLPredictionResult
from app.schemas.evidence import (
    ManipulationTactic,
    NormalizedEvidence,
    UncertaintyReport,
)

# Documented Scoring Weights
WEIGHT_MODEL_A_MAX = 35.0           # Maximum score contribution from SMS/Text spam classifier
WEIGHT_MODEL_B_PHISH_MAX = 45.0     # Maximum score contribution from PhiUSIIL URL classifier
WEIGHT_TACTICS_MAX = 35.0           # Maximum composite contribution from manipulation tactics

# Tactic category caps (each category is counted at most once)
TACTIC_CATEGORY_WEIGHTS = {
    "credential_request": 15.0,
    "identity_inconsistency": 15.0,
    "urgency": 8.0,
    "authority_impersonation": 8.0,
    "secrecy": 10.0,
    "payment_request": 10.0,
}

CORRELATION_DAMPENING_DISCOUNT = 8.0  # Discount applied when Model A spam and heuristic urgency co-occur


class RiskEngine:
    """Configurable, deterministic risk engine for unified threat fusion."""

    def __init__(
        self,
        threshold_high: float = settings.RISK_THRESHOLD_HIGH,
        threshold_suspicious: float = settings.RISK_THRESHOLD_SUSPICIOUS,
    ):
        self.threshold_high = threshold_high
        self.threshold_suspicious = threshold_suspicious

    def compute_risk(
        self,
        msg_result: Optional[MessagePredictionResult],
        url_results: List[URLPredictionResult],
        tactics: List[ManipulationTactic],
        evidence_items: List[NormalizedEvidence],
        has_text: bool,
        has_url: bool,
        has_screenshot: bool = False,
        has_audio: bool = False,
    ) -> Tuple[str, float, Dict[str, Any], UncertaintyReport, List[str], List[str]]:
        """Calculates deterministic composite risk score, verdict, missing checks, and safe next steps.
        
        Returns:
            Tuple of (verdict, score, model_signals, uncertainty_report, missing_checks, safe_next_steps)
        """
        # 1. Inconclusive check for empty/uninformative input
        if not has_text and not has_url and not has_screenshot and not has_audio:
            uncertainty = UncertaintyReport(
                is_uncertain=True,
                uncertainty_level="high",
                reasons=["No input content or modalities provided for analysis."],
                conflicting_signals=[],
            )
            missing = self._generate_missing_checks(has_text=False, has_url=False, has_screenshot=False, has_audio=False)
            steps = ["Submit message text, a suspicious URL, a screenshot, or an audio recording to perform an investigation."]
            return "inconclusive", 0.0, {}, uncertainty, missing, steps

        # 2. Model A Contribution (0.0 to 35.0)
        model_a_points = 0.0
        spam_prob = 0.0
        if msg_result is not None:
            spam_prob = msg_result.spam_probability
            model_a_points = round(spam_prob * WEIGHT_MODEL_A_MAX, 2)

        # 3. Model B Contribution (0.0 to 45.0)
        model_b_points = 0.0
        any_phishing_url = False
        max_phish_prob = 0.0
        phishing_url_count = 0

        for r in url_results:
            if r.phishing_probability > max_phish_prob:
                max_phish_prob = r.phishing_probability
            if r.is_phishing:
                any_phishing_url = True
                phishing_url_count += 1

        if url_results:
            if any_phishing_url:
                primary = max_phish_prob * 40.0
                additional = min(5.0, (phishing_url_count - 1) * 2.5)
                model_b_points = min(WEIGHT_MODEL_B_PHISH_MAX, round(primary + additional, 2))
            else:
                # Legitimate URLs: slight baseline if max phish prob is somewhat elevated
                model_b_points = round(max_phish_prob * 10.0, 2)

        # 4. Manipulation Tactics Contribution (0.0 to 35.0)
        # Deduplicate by category so multiple words in same tactic don't artificially blow up score
        detected_categories = set(t.category for t in tactics)
        raw_tactic_points = 0.0
        for cat in detected_categories:
            raw_tactic_points += TACTIC_CATEGORY_WEIGHTS.get(cat, 5.0)
        tactic_points = min(WEIGHT_TACTICS_MAX, raw_tactic_points)

        # 5. Correlation Dampening:
        # If Model A spam probability is already high (> 0.65) and urgency is detected,
        # damp the co-occurrence so the text is not double-counted for the same lexical features.
        correlation_discount = 0.0
        if spam_prob >= 0.65 and "urgency" in detected_categories:
            correlation_discount = min(tactic_points * 0.25, CORRELATION_DAMPENING_DISCOUNT)

        # 6. Composite Score Calculation
        raw_score = model_a_points + model_b_points + tactic_points - correlation_discount
        score = min(max(round(raw_score, 1), 0.0), 100.0)

        # 7. Conflicting Signals Analysis
        conflicting_signals: List[str] = []
        if msg_result is not None and url_results:
            if not msg_result.is_spam and any_phishing_url:
                conflicting_signals.append(
                    "Message text classified as benign ham, but embedded URL was flagged as malicious phishing."
                )
            elif msg_result.is_spam and not any_phishing_url and max_phish_prob < 0.20:
                conflicting_signals.append(
                    "Message text exhibited strong spam signals, but embedded URL exhibited legitimate lexical structure."
                )

        # 8. Verdict Determination
        # Priority rules:
        # A. High-Risk: score >= threshold_high OR confirmed high-confidence phishing URL OR (credential request + authority/inconsistency)
        has_cred_lure = "credential_request" in detected_categories
        has_auth_spoof = ("authority_impersonation" in detected_categories) or ("identity_inconsistency" in detected_categories)
        has_critical_combo = has_cred_lure and has_auth_spoof

        if score >= self.threshold_high or (any_phishing_url and max_phish_prob >= 0.80) or has_critical_combo:
            verdict = "high-risk"
        elif score >= self.threshold_suspicious or len(detected_categories) >= 2 or any_phishing_url:
            verdict = "suspicious"
        else:
            verdict = "benign"

        # 9. Uncertainty Assessment
        uncertainty_reasons: List[str] = []
        if conflicting_signals:
            uncertainty_reasons.append("Contradictory signals between message language and destination URLs.")
        if not has_url:
            uncertainty_reasons.append("No destination URL available for lexical or domain-level inspection.")
        if has_text and len((msg_result.text if msg_result else "").split()) < 4:
            uncertainty_reasons.append("Short message body with limited lexical context.")

        uncertainty_level = "high" if len(uncertainty_reasons) >= 2 else ("medium" if uncertainty_reasons else "low")
        is_uncertain = len(uncertainty_reasons) > 0

        uncertainty_report = UncertaintyReport(
            is_uncertain=is_uncertain,
            uncertainty_level=uncertainty_level,
            reasons=uncertainty_reasons,
            conflicting_signals=conflicting_signals,
        )

        # 10. Missing Checks Enumeration
        missing_checks = self._generate_missing_checks(
            has_text=has_text,
            has_url=has_url,
            has_screenshot=has_screenshot,
            has_audio=has_audio,
        )

        # 11. Safe Next Steps Guidance
        safe_next_steps = self._generate_safe_steps(verdict, detected_categories, any_phishing_url)

        model_signals = {
            "model_a_sms_classifier": {
                "active": msg_result is not None,
                "label": msg_result.label if msg_result else None,
                "spam_probability": msg_result.spam_probability if msg_result else None,
                "confidence": msg_result.confidence if msg_result else None,
                "points_contributed": model_a_points,
            },
            "model_b_url_classifier": {
                "active": len(url_results) > 0,
                "urls_scanned_count": len(url_results),
                "any_phishing": any_phishing_url,
                "max_phishing_probability": round(max_phish_prob, 4),
                "points_contributed": model_b_points,
            },
            "heuristics_and_tactics": {
                "categories_detected": sorted(list(detected_categories)),
                "raw_tactic_points": raw_tactic_points,
                "capped_tactic_points": tactic_points,
                "correlation_dampening_applied": round(correlation_discount, 2),
            },
            "weights_configuration": {
                "weight_model_a_max": WEIGHT_MODEL_A_MAX,
                "weight_model_b_phish_max": WEIGHT_MODEL_B_PHISH_MAX,
                "weight_tactics_max": WEIGHT_TACTICS_MAX,
                "threshold_high": self.threshold_high,
                "threshold_suspicious": self.threshold_suspicious,
            },
        }

        return verdict, score, model_signals, uncertainty_report, missing_checks, safe_next_steps

    def _generate_missing_checks(
        self,
        has_text: bool,
        has_url: bool,
        has_screenshot: bool,
        has_audio: bool,
    ) -> List[str]:
        """Explicitly enumerates omitted or unavailable security verifications."""
        checks = [
            "Live DNS resolution and WHOIS domain age not queried (passive analysis only).",
            "URL destination not actively visited or crawled (zero live HTTP GET/POST requests).",
            "SSL/TLS certificate chain and Certificate Transparency logs not evaluated.",
            "Dynamic sandbox execution and attachment payload detonation not performed.",
        ]
        if not has_url:
            checks.append("No URL extracted or submitted for lexical phishing inspection.")
        if not has_screenshot:
            checks.append("No screenshot provided (visual UI, layout rendering, and brand logos not analyzed).")
        if not has_audio:
            checks.append("No audio recording provided (acoustic voice biometrics and synthetic speech/deepfake detection not performed).")
        return checks

    def _generate_safe_steps(
        self,
        verdict: str,
        categories: set,
        any_phishing_url: bool,
    ) -> List[str]:
        """Generates prescriptive, actionable user security recommendations."""
        if verdict == "high-risk":
            steps = [
                "CRITICAL: Do not click any links or open any attachments contained in this message.",
                "Never disclose passwords, two-factor OTP codes, PINs, or banking credentials.",
                "Do not reply or use the contact numbers provided inside the communication.",
                "Report this communication to your organization's IT Security Team / SOC.",
                "If credentials were already submitted, immediately navigate to the authentic service and reset your password.",
            ]
        elif verdict == "suspicious":
            steps = [
                "Treat this communication with heightened caution before taking requested actions.",
                "Verify the claim through an independent official channel (e.g., bookmarked website or official app).",
                "Do not input authentication details or process urgent payment requests.",
                "Inspect the true sender address or domain name carefully for subtle spelling discrepancies.",
            ]
        elif verdict == "inconclusive":
            steps = [
                "Analysis inconclusive due to insufficient input data.",
                "Submit additional text context, full message headers, or complete URLs for a comprehensive evaluation.",
            ]
        else:
            steps = [
                "No acute social engineering or phishing markers were detected.",
                "Continue adhering to standard operational security practices.",
                "Remain vigilant if requested to enter credentials or download software in subsequent communications.",
            ]

        if "credential_request" in categories:
            steps.append("Defensive note: Legitimate organizations never request your full password or OTP over SMS or unauthenticated chat.")
        if "payment_request" in categories:
            steps.append("Defensive note: Requests for payment via gift cards or cryptocurrency are virtually always fraudulent.")

        return steps


risk_engine = RiskEngine()
