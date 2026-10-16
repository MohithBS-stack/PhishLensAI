# Product Requirements Document (PRD)
## PhishLens AI — Intelligent Multimodal Phishing & Scam Detection Platform

**Event:** CyberForge Hackathon 2026  
**Team Size:** 2 Members  
**Timeline:** 3–7 Days  
**Status:** Phase 1 - Architecture & Foundation Complete  

---

## 1. Executive Summary
PhishLens AI is an end-to-end, multi-vector phishing and scam defense platform designed to protect individuals and organizations against sophisticated digital deception. While conventional filters target isolated channels (e.g., email spam or domain blacklists), modern threat actors execute coordinated campaigns across SMS/smishing, fraudulent URLs, spoofed credential harvesting pages, and synthetic communications. 

PhishLens AI combines lightweight machine learning classification, heuristic feature extraction, explainable risk scoring, and a modern responsive dashboard to provide instant threat intelligence with actionable remediation guidance.

---

## 2. Problem Statement
- **Multi-Channel Attacks:** Attackers bypass corporate email filters by reaching victims via SMS (smishing), messaging apps, and shortlinks.
- **Evasion of Static Blacklists:** New phishing domains are registered, weaponized, and discarded within hours, rendering reactive blocklists insufficient.
- **Lack of Explainability:** Security warnings rarely explain *why* a message or URL is malicious, resulting in alert fatigue and employee dismissals.
- **Latency & Resource Bottlenecks:** Heavy deep learning architectures are often too slow or expensive for real-time edge or client-side evaluation during rapid incident triage.

---

## 3. Product Vision & Goals

### 3.1 Core Objectives
1. **Real-time Dual Analysis:** Provide sub-150ms evaluation for both suspicious text (SMS/chat messages) and suspect URLs.
2. **Transparent Explainability:** Deconstruct every prediction into interpretable risk indicators (e.g., suspicious brand imitation, high entropy subdomains, urgency markers, absence of SSL, credential harvesting indicators).
3. **Developer-Friendly API:** Offer a clean, versioned REST API (`/api/v1`) for easy integration with corporate SIEMs, Slack bots, and security gateways.
4. **Intuitive Analyst Dashboard:** Deliver a modern frontend for manual triage, batch scanning, payload inspection, and incident audit logging.

### 3.2 Hackathon Constraints & Scope Management
- **Team Size:** 2 members (Engineer 1: ML Pipelines & FastAPI Backend; Engineer 2: Next.js Frontend & Visualizations).
- **Timeline:** 3 to 7 days.
- **Execution Strategy:** Focus strictly on high-impact, high-precision core models (URL classifier trained on PhiUSIIL + SMS/Text classifier trained on SMS Spam Collection) before considering expansion modules (OCR/Image/Vision).

---

## 4. User Personas & Use Cases

### Personas
1. **Everyday Consumer / Employee:** Needs quick, zero-friction verification of a received SMS or SMS-embedded URL ("Is this bank alert real?").
2. **Security Analyst (SOC Tier 1):** Triages reported employee phishing alerts, needs instant indicator breakdown and structured JSON output.
3. **Platform Developer:** Integrates automated scam detection into messaging webhooks or automated customer support queues.

### Key Use Cases
- **UC-1: Instant SMS Scan:** User pastes an SMS ("URGENT: Your account is suspended. Click http://..."). System scores text urgency, flags spam patterns, and extracts & analyzes nested URLs.
- **UC-2: URL Deep Inspection:** User enters a suspicious URL. System inspects lexical features, domain entropy, obfuscation, TLD reputation, and structural patterns.
- **UC-3: Unified Risk Assessment:** If both message text and embedded URLs are present, the system calculates a weighted composite risk score with granular warning badges.

---

## 5. Functional Requirements

### 5.1 Backend Services (FastAPI)
- **FR-1 Health & Telemetry:** `GET /health` returns service status, environment, version, uptime, and loaded model metadata.
- **FR-2 URL Analysis Endpoint:** `POST /api/v1/scan/url` accepts a URL string, validates scheme/syntax, extracts lexical/structural features, passes features through the trained URL model, and outputs a threat score (0–100%), classification (`phishing` vs `legitimate`), confidence, and feature attribution.
- **FR-3 Text/SMS Analysis Endpoint:** `POST /api/v1/scan/text` accepts raw text, cleanses input, applies TF-IDF/vectorization, passes through the trained text classifier, and outputs classification (`spam/phishing` vs `ham`), confidence score, and detected risk keywords.
- **FR-4 Multi-Modal Unified Scan:** `POST /api/v1/scan/unified` accepts text containing URLs, orchestrates simultaneous text and URL analysis, and outputs composite severity and mitigation steps.
- **FR-5 Error Handling:** Standardized error responses with error codes, human-readable details, and request tracking IDs.

### 5.2 Frontend Dashboard (Next.js & TypeScript)
- **FR-6 Unified Scanner Interface:** Interactive input card with instant tabbed switching between "Quick Text / SMS Scan", "URL Deep Scan", and "Batch Inspection".
- **FR-7 Visual Threat Breakdown:** Visual gauge meter (Low / Medium / High / Critical Risk), color-coded badge tags, and breakdown of specific risk flags.
- **FR-8 Audit & History Log:** Local storage or session-based log of recent scans with exportable JSON report.
- **FR-9 Responsive & Accessible Design:** Clean dark/light theme, high-contrast indicators, and mobile-friendly layouts.

---

## 6. Non-Functional Requirements
- **Performance:** P95 response time under 200ms for standard inference endpoints.
- **Reliability:** Graceful error handling; backend survives malformed URLs, oversized inputs, and non-ASCII character sets without unhandled 500 exceptions.
- **Security:** Strict input sanitization, rate limiting, no dynamic code execution, and absolute separation of secret keys via Pydantic settings.
- **Maintainability:** Modular architecture adhering to single-responsibility principles, typed data contracts, and automated unit/integration test coverage (>80%).

---

## 7. Success Metrics & Hackathon KPIs
- **Accuracy:** >95% F1-score on PhiUSIIL URL benchmark validation set; >97% F1-score on SMS Spam validation set.
- **Inference Speed:** Average processing time < 100ms per request.
- **Demo Readiness:** Zero-dependency live demo flow showing real-time detection of zero-day phishing samples and live explainability telemetry.
