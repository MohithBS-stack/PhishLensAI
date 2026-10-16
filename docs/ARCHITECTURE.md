# System Architecture Document
## PhishLens AI — System Architecture & Component Design

**Project:** PhishLens AI  
**Hackathon:** CyberForge 2026  
**Document Version:** 1.0.0  

---

## 1. High-Level Architectural Overview

PhishLens AI is designed as a decoupled, multi-tier distributed micro-architecture comprising:
1. **Presentation Tier (Frontend):** Next.js 14+ (App Router) + TypeScript + Tailwind CSS / Modern CSS, providing interactive dashboards, real-time threat gauges, and incident logs.
2. **Application & API Gateway Tier (Backend):** Python 3.12+ / 3.14+ with FastAPI, Pydantic v2 Settings & Schema validation, structured error handlers, and CORS management.
3. **Inference & Intelligence Tier (ML Pipeline):** Scikit-learn / LightGBM pipelines serializing lightweight models with pre-computed feature extractors for sub-millisecond scoring.
4. **Data & Storage Tier:** Local file cache / session storage for fast prototyping, with clean abstractions for PostgreSQL or Redis integration in production.

```
+-------------------------------------------------------------------------+
|                         Next.js 14+ Frontend                            |
|    - Threat Scanner Card (SMS / URL / Unified)                          |
|    - Explainable Threat Score Gauges & Risk Breakdown Badges            |
|    - Scan History & Export Telemetry                                    |
+------------------------------------+------------------------------------+
                                     | HTTP / JSON REST APIs
                                     v
+-------------------------------------------------------------------------+
|                         FastAPI Core Service                            |
|  +-------------------------------------------------------------------+  |
|  | Middleware: CORS, Request ID, Rate Limiting, Error Handling       |  |
|  +-------------------------------------------------------------------+  |
|  | Routers:                                                          |  |
|  |   - /health                 -> Service Status & Metadata          |  |
|  |   - /api/v1/scan/url        -> Lexical + PhiUSIIL ML Inference    |  |
|  |   - /api/v1/scan/text       -> NLP / TF-IDF + SMS Spam ML         |  |
|  |   - /api/v1/scan/unified    -> Composite Multi-Vector Analysis    |  |
|  +-------------------------------------------------------------------+  |
|  | Core Services:                                                    |  |
|  |   - URL Feature Extraction (Entropy, TLD, Lexical, Heuristics)    |  |
|  |   - Text Processing (Tokenizer, Urgency Detection, Regex Links)   |  |
|  |   - Model Registry & Inference Service                            |  |
+------------------------------------+------------------------------------+
                                     | Loads Models (Read-Only)
                                     v
+-------------------------------------------------------------------------+
|                       Offline Model Artifacts                           |
|   - URL Model (trained on PhiUSIIL 235k dataset)                        |
|   - SMS Model (trained on SMSSpamCollection 5.5k corpus)                |
+-------------------------------------------------------------------------+
```

---

## 2. Directory Structure

```
PhishLensAI/
│
├── .gitignore                      # Standardized ignores for data/models/caches
├── README.md                       # High-level repo summary & onboarding
├── docs/                           # Architecture, PRD, Strategy, Security
│   ├── PRD.md
│   ├── ARCHITECTURE.md
│   ├── IMPLEMENTATION_PLAN.md
│   ├── DATASET_STRATEGY.md
│   └── SECURITY.md
│
├── datasets/                       # Data storage (gitignored raw & processed)
│   ├── raw/
│   │   ├── phiusiil/
│   │   │   └── PhiUSIIL_Phishing_URL_Dataset.csv
│   │   └── sms_spam/
│   │       ├── SMSSpamCollection
│   │       └── readme
│   └── processed/                  # Cleaned, standardized training splits
│
├── backend/                        # FastAPI Application
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI application factory
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py           # Pydantic v2 BaseSettings
│   │   │   └── errors.py           # Custom exceptions & handlers
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── router.py       # API v1 central router
│   │   │       └── endpoints/
│   │   │           ├── __init__.py
│   │   │           ├── health.py   # /health endpoint
│   │   │           ├── url_scan.py # Future /scan/url
│   │   │           └── text_scan.py# Future /scan/text
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   ├── health.py           # Health response schemas
│   │   │   └── scan.py             # Request & response contracts
│   │   └── services/
│   │       ├── __init__.py
│   │       └── model_registry.py   # Model loading abstraction
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py             # Pytest fixtures
│   │   └── test_health.py          # Health check & error tests
│   ├── requirements.txt            # Python dependencies
│   └── .env.example                # Example environment variables
│
└── frontend/                       # Next.js Dashboard
    ├── package.json
    ├── tsconfig.json
    ├── next.config.js
    ├── app/
    │   ├── layout.tsx
    │   ├── page.tsx                # Unified Threat Scanner UI
    │   └── globals.css
    ├── components/
    │   ├── Navbar.tsx
    │   ├── ThreatScoreGauge.tsx
    │   ├── ThreatIndicators.tsx
    │   └── ScanHistory.tsx
    └── lib/
        └── api.ts                  # Typed client for backend API
```

---

## 3. Component Details & Design Contracts

### 3.1 Backend Configuration Management (`backend/app/core/config.py`)
Utilizes `pydantic-settings` to provide type-safe, validated runtime configurations:
- `PROJECT_NAME`: "PhishLens AI API"
- `VERSION`: "1.0.0"
- `API_V1_PREFIX`: "/api/v1"
- `ENVIRONMENT`: "development" | "production" | "testing"
- `CORS_ORIGINS`: Validated list of permitted origins (e.g. `["http://localhost:3000"]`)
- `HOST`: "0.0.0.0"
- `PORT`: 8000

### 3.2 Error Handling Contract (`backend/app/core/errors.py`)
All error responses conform to a predictable structure:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The provided URL is malformed or invalid.",
    "status_code": 422,
    "request_id": "req-98f98d-a41",
    "timestamp": "2026-10-13T17:00:00Z",
    "details": {}
  }
}
```

### 3.3 Health Endpoint Contract (`GET /health`)
```json
{
  "status": "healthy",
  "app_name": "PhishLens AI API",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2026-10-13T17:00:00Z",
  "system": {
    "python_version": "3.14.2",
    "platform": "Windows"
  },
  "models_loaded": {
    "url_classifier": false,
    "sms_classifier": false
  }
}
```

---

## 4. Scalability & Extensibility Principles

1. **Decoupled Training & Serving:**
   - Training scripts in `scripts/` produce portable serialized pipelines (Scikit-Learn/LightGBM).
   - The FastAPI backend only reads pre-serialized `.joblib` / `.onnx` artifacts and never runs heavy training routines during request cycles.
2. **Fast Feature Extraction:**
   - Heuristic and lexical extractors are implemented in pure Python with pre-compiled regex for maximum throughput.
3. **Clean Contract Typing:**
   - Pydantic v2 schemas strictly validate every incoming request body and guarantee type safety for frontend consumers.
