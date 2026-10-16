# Implementation Plan
## PhishLens AI — Hackathon Roadmap & Milestone Execution

**Event:** CyberForge Hackathon 2026  
**Timeline:** 3–7 Days  
**Team Composition:** 2 Engineers  
- **Engineer A:** Backend Infrastructure, ML Pipeline Engineering, Model Training & Serialization  
- **Engineer B:** Frontend Application, Data Visualizations, Threat Explainability UI, API Integration  

---

## 1. Phase Breakdown & Timeline Matrix

| Phase | Title | Duration | Primary Focus | Status |
|---|---|---|---|---|
| **Phase 1** | **Foundation & Architecture** | Day 1 | Data validation, docs, backend scaffold, frontend scaffold, tests | **COMPLETED** |
| **Phase 2** | **Data Preprocessing & ML Pipelines** | Day 2–3 | Feature engineering, model training (PhiUSIIL & SMS), evaluation | **COMPLETED** |
| **Phase 3** | **Multimodal OCR & Audio Services** | Day 3–4 | Screenshot OCR, audio transcription, message-analysis reuse | **COMPLETED** |
| **Phase 4** | **Unified Evidence Fusion & Explainability** | Day 4–5 | Normalized evidence, manipulation detection, risk engine, LLM explanation | **COMPLETED** |
| **Phase 5** | **Frontend Integration & Hardening** | Day 5–6 | Unified workspace, results dashboard, hardening, E2E tests | **COMPLETED** |
| **Phase 6** | **Deployment Readiness & Live Demo** | Day 6–7 | Render/Vercel blueprints, verification scripts, pitch demo script | **COMPLETED** |

---

## 2. Phase 1: Foundation & Architecture (Current Phase)

### Deliverables:
- [x] Workspace inspection and preservation of raw assets.
- [x] Dataset file discovery, size quantification, schema validation, and missing path reporting.
- [x] Validation of `SMSSpamCollection` (tab-separated, 5,574 rows; 4,827 ham, 747 spam).
- [x] Inspection of `PhiUSIIL_Phishing_URL_Dataset.csv` (235,795 rows, 56 columns; label 0=phishing, 1=legitimate; 0 missing values).
- [x] Comprehensive documentation suite:
  - `docs/PRD.md`
  - `docs/ARCHITECTURE.md`
  - `docs/IMPLEMENTATION_PLAN.md`
  - `docs/DATASET_STRATEGY.md`
  - `docs/SECURITY.md`
- [x] Root `.gitignore` hardening (excluding datasets, models, environments, caches).
- [x] Minimal modular FastAPI backend with Pydantic settings, `GET /health`, custom error handling, and unit test suite.
- [x] Next.js + TypeScript frontend scaffold.
- [x] Automated test execution and verification.

---

## 3. Phase 2: Data Preprocessing & Model Training (Next Phase)

### Objectives:
1. **SMS Spam Pipeline:**
   - Text cleaning, lowercasing, punctuation normalization, phone number / URL tokenization.
   - TF-IDF n-gram vectorizer (unigrams + bigrams) with sublinear TF scaling.
   - Benchmark Logistic Regression, Multinomial Naive Bayes, and LightGBM.
   - Serialize best pipeline (`sms_pipeline.joblib`) with vocabulary and calibrator.
2. **PhiUSIIL URL Pipeline:**
   - Evaluate feature importance across the 54 numerical/lexical features in PhiUSIIL.
   - Build a lightweight standalone feature extractor capable of computing the key top 15–20 URL features on the fly for incoming raw URLs.
   - Train an optimized LightGBM / Random Forest classifier.
   - Evaluate precision/recall trade-off (prioritize low false-positive rate on legitimate sites).
   - Serialize URL model artifact (`url_classifier.joblib`).

---

## 4. Phase 3: Core API Inference & Heuristic Engine

### Objectives:
1. **URL Feature Extractor Service:**
   - Real-time lexical analysis: length, entropy, IP in domain, suspicious TLDs (`.xyz`, `.top`, `.tk`), obfuscation counts, brand keyword matching.
2. **Text Heuristic & Urgency Engine:**
   - Detect urgency markers ("account suspended", "immediate action required", "verify now"), financial cues ("crypto", "wire", "gift card").
   - Extract embedded URLs automatically using regex.
3. **Inference Endpoints:**
   - `POST /api/v1/scan/url`
   - `POST /api/v1/scan/text`
   - `POST /api/v1/scan/unified`
4. **Structured Explainability:**
   - Return SHAP-like or heuristic factor weights explaining what contributed most to the risk score.

---

## 5. Phase 4: Frontend Dashboard & Visualization

### Objectives:
1. **Next.js Dashboard Components:**
   - Interactive Input Panel: Instant paste for SMS, Emails, or raw URLs.
   - Live Threat Gauge: Animated circular SVG gauge indicating 0–100% Risk Score.
   - Risk Factor Matrix: Categorized badges (e.g., "Urgency Trigger Detected", "High Domain Entropy", "Unverified TLD").
   - Remediation Playbook: Dynamic guidance cards (e.g., "Do not click", "Forward to IT Security", "Report sender").
2. **Batch & History Module:**
   - Client-side history drawer allowing analysts to compare recent scans.
   - Export scan report to JSON or Markdown.

---

## 6. Phase 5: Hardening, Benchmarking & Presentation

### Objectives:
1. **Stress & Latency Testing:** Benchmark FastAPI endpoints under concurrent requests using Locust or pytest-benchmark.
2. **Security Audit:** Run Bandit and ESLint checks. Ensure zero secret leakage.
3. **Demo & Slide Deck:**
   - 3-minute video / live demonstration script.
   - Real zero-day attack simulations vs benign controls.
