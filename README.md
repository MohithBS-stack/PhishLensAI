# PhishLens AI 🛡️
### Intelligent Multimodal Phishing & Scam Detection Platform
**Event:** CyberForge Hackathon 2026 | **Team:** 2 Members | **Status:** Phases 1–5 Complete

---

## 📌 Project Overview
**PhishLens AI** is an intelligent, explainable cybersecurity threat analysis platform that detects and explains digital deception across multiple threat modalities (SMS smishing, fraudulent URLs, screenshot OCR, and voicemail audio transcription).

Rather than acting as an opaque black-box detector or relying on stale domain blacklists, PhishLens AI pairs lightweight machine learning classifiers with evidence-backed psychological manipulation detection, deterministic threat scoring, and structured AI briefings.

---

## 🏗️ Architecture & Core Components

```
+-------------------------------------------------------------------------+
|                  Next.js 16 (Turbopack) + TypeScript                    |
|   - Multimodal Investigation Workspace (Text, URL, Screenshot, Audio)  |
|   - Real-Time Circular Threat Gauge & Color-Coded Verdict Banner        |
|   - Evidence Register (Grouped by Modality, Observed vs Inferred)       |
|   - Psychological Manipulation Detection (Urgency, Authority, OTP, etc.)|
|   - Model Telemetry & Deterministic Score Weight Allocation Cards       |
|   - Exportable Report (JSON Download + Markdown Clipboard Copy)         |
|   - Local Browser Session History Drawer (with explicit non-persistence)|
+------------------------------------+------------------------------------+
                                     | REST API (HTTP / JSON / Multipart)
                                     v
+-------------------------------------------------------------------------+
|                         FastAPI Core Engine                             |
|  - Middleware: Restrictive CORS, Request ID Tracking, Global Exception  |
|  - POST /api/v1/scan/unified       -> JSON Unified Text + URL Scan      |
|  - POST /api/v1/scan/investigate   -> Multipart Multimodal Investigation|
|  - POST /api/v1/scan/text          -> Text Spam & URL Extraction        |
|  - POST /api/v1/scan/screenshot    -> In-Memory Magic Byte OCR Analysis |
|  - POST /api/v1/scan/audio         -> Non-Persistent Audio STT Analysis |
|  - GET  /health                    -> Health & Loaded Models Telemetry  |
+------------------------------------+------------------------------------+
                                     |
               +---------------------+---------------------+
               v                                           v
+-----------------------------+             +-----------------------------+
|    Trained ML Artifacts     |             | Deterministic Risk Engine   |
| - Model A: SMS Spam NLP     |             | - Documented Weights        |
|   (TF-IDF + Calibrated NB)  |             | - Correlation Dampening     |
| - Model B: PhiUSIIL URL     |             | - Tactic Category Caps      |
|   (Lexical Feature Clf)     |             | - Uncalibrated Disclosures  |
+-----------------------------+             +-----------------------------+
```

---

## ⚙️ Environment Configuration

### Backend (`backend/.env`)
```bash
PROJECT_NAME="PhishLens AI API"
VERSION="1.0.0"
ENVIRONMENT="development"
DEBUG=true
API_V1_PREFIX="/api/v1"
HOST="0.0.0.0"
PORT=8000

# CORS Allowed Origins
CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000"]

# Model paths
URL_MODEL_PATH="models/saved/url_classifier.joblib"
SMS_MODEL_PATH="models/saved/sms_classifier.joblib"

# Optional LLM Explanation (Falls back to deterministic generator if omitted)
GEMINI_API_KEY=""
GEMINI_MODEL="gemini-2.5-flash"
ENABLE_LLM_EXPLANATION=true
LLM_TIMEOUT_SECONDS=5.0

# Deterministic Risk Scoring Thresholds
RISK_THRESHOLD_HIGH=70.0
RISK_THRESHOLD_SUSPICIOUS=30.0
```

### Frontend (`frontend/.env.local`)
```bash
NEXT_PUBLIC_API_URL="http://localhost:8000"
```

---

## 🚀 Quickstart Guide

### 1. Backend Service (FastAPI)
```bash
cd backend

# Run the complete test suite (43 unit & integration tests)
py -m pytest tests -v

# Start the development server
py -m uvicorn app.main:app --reload --port 8000
```
* Interactive API Documentation (Swagger UI): `http://localhost:8000/docs`
* Health Endpoint: `http://localhost:8000/health`

### 2. Frontend Dashboard (Next.js)
```bash
cd frontend

# Build production bundle
npm run build

# Start local server
npm run dev
```
* Dashboard URL: `http://localhost:3000`

---

## 🧪 Manual Local Smoke-Test Checklist

| Test Item | Steps | Expected Outcome |
|---|---|---|
| **1. Service Telemetry** | Load `http://localhost:3000` with backend running on port 8000 | Top-right status pill glows green (`Backend API Online`) |
| **2. Benign Preset** | Click `Benign` preset button and click `Run Unified Investigation` | Verdict: `BENIGN`, Score `< 30.0`, zero manipulation tactics, low uncertainty |
| **3. Phishing Preset** | Click `PayPal Phish` preset and click `Run Unified Investigation` | Verdict: `HIGH-RISK`, Score `≥ 70.0`, Urgency and Brand Mismatch tactics detected |
| **4. IRS Scam Preset** | Click `IRS Scam` preset and click `Run Unified Investigation` | Detects Authority Impersonation, Secrecy Demand, and Gift Card payment requests |
| **5. Multimodal File Ingestion** | Upload a screenshot (PNG/JPEG) or audio file (WAV/MP3) | Form submits via `/api/v1/scan/investigate`, populating Screenshot/Audio evidence tabs |
| **6. Report Export** | Click `Copy Summary (MD)` and `Export JSON Report` | Markdown summary copied to clipboard; JSON file downloaded cleanly |
| **7. Session History** | Run multiple scans | Previous scans appear in `Local Session History` drawer; clicking a case restores its report |

---

## 🛡️ Known Boundaries & Limitations

1. **Passive Evaluation Only:** PhishLens AI never sends active HTTP requests or visits submitted URLs, preventing attacker tracking, honeypot triggering, or zero-day exploitation.
2. **Uncalibrated Model Probabilities:** Model A and Model B output raw probabilistic scores that are not formally calibrated. Composite threat scores are deterministic heuristic ratings (0–100) and explicitly disclosed as such in every report.
3. **Speech-to-Text Scope:** Audio analysis evaluates transcribed spoken content for scam cues; it does not perform synthetic voice cloning or acoustic deepfake biometric detection.
4. **Session-Scoped History:** Case history is maintained strictly in client-side browser session memory; no cases or uploaded payloads are permanently logged or stored on the backend.
