"""Unified Threat Scanner & Evidence Fusion Service for PhishLens AI.

Orchestrates multi-vector investigations across text, URLs, screenshot OCR, and audio transcription.
Implements:
1. Graceful handling of missing or partial modalities.
2. Non-redundant execution and deduplication of URLs, texts, and evidence signals.
3. Deterministic risk calculation and verdict synthesis via RiskEngine.
4. Grounded threat explanation generation.
"""
from typing import List, Dict, Any, Optional
import uuid

from app.ml.inference import inference_engine, MessagePredictionResult, URLPredictionResult
from app.services.message_analysis import message_analysis_service
from app.services.ocr_service import ocr_service
from app.services.audio_service import audio_service
from app.services.manipulation_detector import manipulation_detector
from app.services.risk_engine import risk_engine
from app.services.explanation_service import explanation_service
from app.schemas.evidence import (
    NormalizedEvidence,
    ManipulationTactic,
    StructuredExplanation,
    UncertaintyReport,
    UnifiedReportResponse,
)


class UnifiedScannerService:
    """Coordinates multimodal threat analysis and synthesizes unified evidence reports."""

    async def investigate(
        self,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        screenshot_bytes: Optional[bytes] = None,
        screenshot_filename: Optional[str] = None,
        screenshot_content_type: Optional[str] = None,
        audio_bytes: Optional[bytes] = None,
        audio_filename: Optional[str] = None,
        audio_content_type: Optional[str] = None,
        audio_stt_engine: Optional[str] = None,
        include_explanation: bool = True,
    ) -> UnifiedReportResponse:
        """Executes unified multimodal threat investigation and returns comprehensive evidence report."""
        case_id = f"case-{uuid.uuid4().hex[:12]}"
        evidence_by_modality: Dict[str, List[NormalizedEvidence]] = {
            "text": [],
            "url": [],
            "screenshot": [],
            "audio": [],
        }
        all_tactics: List[ManipulationTactic] = []
        raw_text_corpus: List[str] = []
        collected_urls: List[str] = list(urls or [])

        has_user_text = bool(text and text.strip())
        has_screenshot = bool(screenshot_bytes)
        has_audio = bool(audio_bytes)

        if has_user_text:
            cleaned_input_text = text.strip()
            raw_text_corpus.append(cleaned_input_text)

        # 1. Process Screenshot Modality (if provided)
        if has_screenshot:
            ocr_res = await ocr_service.process_screenshot(
                file_bytes=screenshot_bytes,
                filename=screenshot_filename or "screenshot.png",
                content_type=screenshot_content_type or "image/png",
            )
            extracted_ocr_text = ocr_res.extracted_text.strip()
            if extracted_ocr_text:
                raw_text_corpus.append(extracted_ocr_text)

            evidence_by_modality["screenshot"].append(
                NormalizedEvidence(
                    evidence_id=f"ev-ocr-{uuid.uuid4().hex[:8]}",
                    source_modality="screenshot",
                    indicator_type="screenshot_ocr_metadata",
                    description=(
                        f"Image ingested ({ocr_res.image_width}x{ocr_res.image_height}, {ocr_res.size_bytes} bytes). "
                        f"OCR Engine '{ocr_res.ocr_engine}' detected {len(extracted_ocr_text)} characters."
                    ),
                    supporting_excerpt=extracted_ocr_text[:120] if extracted_ocr_text else "No text detected",
                    severity="low" if extracted_ocr_text else "medium",
                    evidence_source=f"ocr_service:{ocr_res.ocr_engine}",
                    confidence=0.95,
                    observed_versus_inferred="observed",
                    limitations_and_missing_checks=[
                        "OCR extracts textual tokens only; visual logo spoofing and layout styling not evaluated.",
                        "Text accuracy subject to image resolution, blur, and font rendering.",
                    ],
                )
            )

        # 2. Process Audio Modality (if provided)
        if has_audio:
            audio_res = await audio_service.process_audio(
                file_bytes=audio_bytes,
                filename=audio_filename or "recording.wav",
                content_type=audio_content_type or "audio/wav",
                engine=audio_stt_engine,
            )
            transcribed_text = audio_res.transcript.strip()
            if transcribed_text:
                raw_text_corpus.append(transcribed_text)

            evidence_by_modality["audio"].append(
                NormalizedEvidence(
                    evidence_id=f"ev-aud-{uuid.uuid4().hex[:8]}",
                    source_modality="audio",
                    indicator_type="audio_transcription_metadata",
                    description=(
                        f"Audio recording processed ({audio_res.duration_seconds:.1f}s, {audio_res.sample_rate}Hz, {audio_res.channels}ch). "
                        f"STT Engine '{audio_res.stt_engine}' transcribed {len(transcribed_text)} characters."
                    ),
                    supporting_excerpt=transcribed_text[:120] if transcribed_text else "No speech detected",
                    severity="low" if transcribed_text else "medium",
                    evidence_source=f"audio_service:{audio_res.stt_engine}",
                    confidence=0.90,
                    observed_versus_inferred="observed",
                    limitations_and_missing_checks=[
                        "Speech-to-text transcribes conversational text; voice biometrics and deepfake cloning checks omitted.",
                        "Transcription fidelity depends on acoustic background noise and speaker clarity.",
                    ],
                )
            )

        # 3. Aggregate and Deduplicate Text & Extract URLs Passively
        combined_text = " ".join(raw_text_corpus).strip()

        for snippet in raw_text_corpus:
            found_urls = message_analysis_service.extract_urls(snippet)
            for u in found_urls:
                if u not in collected_urls:
                    collected_urls.append(u)

        # Canonical distinct URLs list
        unique_urls: List[str] = []
        for u in collected_urls:
            cleaned_u = u.strip()
            if cleaned_u and cleaned_u not in unique_urls:
                unique_urls.append(cleaned_u)

        has_url = len(unique_urls) > 0

        # 4. Model B URL Analysis (live lexical evaluation without visiting)
        url_predictions: List[URLPredictionResult] = []
        for url_str in unique_urls:
            url_pred = inference_engine.predict_url(url_str)
            url_predictions.append(url_pred)

            sev = "critical" if (url_pred.is_phishing and url_pred.confidence >= 0.75) else ("high" if url_pred.is_phishing else "low")
            evidence_by_modality["url"].append(
                NormalizedEvidence(
                    evidence_id=f"ev-url-{uuid.uuid4().hex[:8]}",
                    source_modality="url",
                    indicator_type="url_lexical_analysis",
                    description=(
                        f"URL evaluated as {url_pred.label.upper()} with "
                        f"{url_pred.phishing_probability * 100:.1f}% phishing probability."
                    ),
                    supporting_excerpt=url_str,
                    severity=sev,
                    evidence_source="model_b_phiusiil_classifier",
                    confidence=url_pred.confidence,
                    observed_versus_inferred="inferred",
                    limitations_and_missing_checks=[
                        "Lexical pattern analysis only; domain was NOT visited or crawled over HTTP/HTTPS.",
                        "Live DNS, WHOIS registration age, and SSL certificate chains not queried.",
                    ],
                )
            )

        # 5. Model A Message Classification (NLP spam & suspicious pattern analysis)
        msg_result: Optional[MessagePredictionResult] = None
        if combined_text:
            msg_result = inference_engine.predict_message(combined_text)
            sev = "high" if (msg_result.is_spam and msg_result.spam_probability >= 0.80) else ("medium" if msg_result.is_spam else "low")
            evidence_by_modality["text"].append(
                NormalizedEvidence(
                    evidence_id=f"ev-msg-{uuid.uuid4().hex[:8]}",
                    source_modality="text",
                    indicator_type="message_spam_classifier",
                    description=(
                        f"Message body classified as {msg_result.label.upper()} with "
                        f"{msg_result.spam_probability * 100:.1f}% spam probability."
                    ),
                    supporting_excerpt=combined_text[:140],
                    severity=sev,
                    evidence_source="model_a_sms_classifier",
                    confidence=msg_result.confidence,
                    observed_versus_inferred="inferred",
                    limitations_and_missing_checks=[
                        "Evaluated using TF-IDF n-gram vectorizer trained on SMS/message corpora.",
                        "Long-form multi-paragraph business emails may deviate from SMS distribution.",
                    ],
                )
            )

        # 6. Manipulation & Social Engineering Detection
        if combined_text or unique_urls:
            tactics, tactic_evidences = manipulation_detector.detect_tactics(
                text=combined_text,
                urls=unique_urls,
                source_modality="text" if has_user_text else ("screenshot" if has_screenshot else "audio"),
            )
            all_tactics.extend(tactics)
            for ev in tactic_evidences:
                mod = ev.source_modality
                if mod in evidence_by_modality:
                    evidence_by_modality[mod].append(ev)
                else:
                    evidence_by_modality["text"].append(ev)

        # 7. Deduplicate Evidence Across Modalities
        master_evidence: List[NormalizedEvidence] = []
        seen_evidence_keys = set()

        for mod, items in evidence_by_modality.items():
            for item in items:
                dedup_key = (item.indicator_type, (item.supporting_excerpt or "").strip().lower()[:100])
                if dedup_key not in seen_evidence_keys:
                    seen_evidence_keys.add(dedup_key)
                    master_evidence.append(item)

        # 8. Distinct Supporting Excerpts
        supporting_excerpts: List[str] = []
        seen_excerpts = set()
        for ev in master_evidence:
            if ev.supporting_excerpt:
                clean_exc = ev.supporting_excerpt.strip()
                if clean_exc and clean_exc not in seen_excerpts:
                    seen_excerpts.add(clean_exc)
                    supporting_excerpts.append(clean_exc)

        for t in all_tactics:
            clean_t = t.supporting_evidence.strip()
            if clean_t and clean_t not in seen_excerpts:
                seen_excerpts.add(clean_t)
                supporting_excerpts.append(clean_t)

        # 9. Deterministic Risk Engine Scoring
        verdict, score, model_signals, uncertainty, missing_checks, safe_next_steps = risk_engine.compute_risk(
            msg_result=msg_result,
            url_results=url_predictions,
            tactics=all_tactics,
            evidence_items=master_evidence,
            has_text=bool(combined_text),
            has_url=has_url,
            has_screenshot=has_screenshot,
            has_audio=has_audio,
        )

        # 10. Generate Grounded Threat Explanation
        if include_explanation:
            explanation = await explanation_service.generate_explanation(
                verdict=verdict,
                score=score,
                tactics=all_tactics,
                evidence_items=master_evidence,
                safe_next_steps=safe_next_steps,
                untrusted_text=combined_text or (unique_urls[0] if unique_urls else ""),
                model_signals=model_signals,
            )
        else:
            explanation = explanation_service.generate_deterministic_explanation(
                verdict=verdict,
                score=score,
                tactics=all_tactics,
                evidence_items=master_evidence,
                safe_next_steps=safe_next_steps,
                untrusted_text=combined_text,
            )

        return UnifiedReportResponse(
            case_id=case_id,
            verdict=verdict,
            score=score,
            evidence_by_modality=evidence_by_modality,
            all_evidence=master_evidence,
            manipulation_tactics=all_tactics,
            supporting_excerpts=supporting_excerpts,
            model_signals=model_signals,
            missing_checks=missing_checks,
            uncertainty=uncertainty,
            safe_next_steps=safe_next_steps,
            explanation=explanation,
        )


unified_scanner_service = UnifiedScannerService()
