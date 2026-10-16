# Production Deployment & Rollback Guide

**Platforms:** Render (FastAPI Backend) & Vercel (Next.js Frontend)  
**Hackathon Event:** CyberForge 2026  
**Status:** Deployment-Ready Architecture

---

## 1. System Requirements & Runtime Matrix

| Component | Target Platform | Runtime Version | Memory Requirement | Artifact Footprint |
|---|---|---|---|---|
| **Backend API** | [Render](https://render.com) | Python 3.12+ / 3.14+ | $\ge$ 512 MB RAM | ~787 KB total for both models |
| **Frontend UI** | [Vercel](https://vercel.com) | Node.js 20+ / Next.js 16 | $\ge$ 256 MB RAM | Static Edge Build |

---

## 2. Pre-Deployment Artifact Verification

Before deploying the backend, verify the model artifacts and their SHA-256 cryptographic hashes:

```bash
# From workspace root:
py scripts/verify_artifacts.py
```

Expected Output:
```text
[*] Checking model artifacts in: .../models/saved
[OK] VERIFIED: sms_classifier.joblib (227508 bytes) matches expected SHA-256: dff70e37c5dfd6eb...
[OK] VERIFIED: url_classifier.joblib (559281 bytes) matches expected SHA-256: f98952073aa236c1...
[OK] VERIFIED: metadata.json (762 bytes) matches expected SHA-256: 0fed19cc7c78479c...
[OK] All model artifacts verified successfully. Safe for deployment.
```

---

## 3. Backend Deployment to Render

### Option A: Automatic Blueprint Deployment (`render.yaml`)
1. Push this repository to GitHub or GitLab.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** > **Blueprint**.
3. Connect your repository. Render will automatically parse [`render.yaml`](file:///c:/Users/mohit/OneDrive/Desktop/PhishLensAI/render.yaml) and configure the `phishlens-ai-backend` web service.
4. Click **Apply**.

### Option B: Manual Web Service Setup
1. In the Render Dashboard, click **New +** > **Web Service**.
2. Connect your Git repository.
3. Configure the service settings:
   * **Name:** `phishlens-ai-backend`
   * **Region:** Oregon (US West) or closest region
   * **Branch:** `main`
   * **Root Directory:** Leave blank (repository root)
   * **Runtime:** `Python`
   * **Build Command:** `pip install -r backend/requirements.txt`
   * **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT --app-dir backend --limit-concurrency 50 --timeout-keep-alive 15`
   * **Health Check Path:** `/health`
4. Set Environment Variables in Render:

| Key | Example Value | Description |
|---|---|---|
| `PYTHON_VERSION` | `3.12.0` | Target Python runtime |
| `ENVIRONMENT` | `production` | Production environment flag |
| `DEBUG` | `false` | Disable debug stack traces |
| `CORS_ORIGINS` | `["https://your-frontend.vercel.app"]` | Restrictive allowed CORS origins |
| `URL_MODEL_PATH` | `models/saved/url_classifier.joblib` | Model B artifact path |
| `SMS_MODEL_PATH` | `models/saved/sms_classifier.joblib` | Model A artifact path |
| `ENABLE_LLM_EXPLANATION` | `true` | Enable explanation generator |
| `LLM_TIMEOUT_SECONDS` | `5.0` | Strict timeout before engaging fallback |
| `GEMINI_API_KEY` | *(Secret Key)* | Optional Google Gemini API key |

5. Click **Create Web Service**. Note the assigned URL: `https://phishlens-ai-backend.onrender.com`.

---

## 4. Frontend Deployment to Vercel

1. In the [Vercel Dashboard](https://vercel.com), click **Add New...** > **Project**.
2. Import your GitHub repository.
3. In Project Settings:
   * **Framework Preset:** `Next.js`
   * **Root Directory:** `frontend`
   * **Build Command:** `next build` (default)
   * **Output Directory:** `.next` (default)
4. Add Environment Variable:

| Key | Value | Notes |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `https://phishlens-ai-backend.onrender.com` | URL of deployed Render backend |

5. Click **Deploy**. Vercel will build and assign your production domain: `https://phishlens-ai.vercel.app`.
6. Return to Render and update the backend's `CORS_ORIGINS` variable with your actual Vercel domain!

---

## 5. Post-Deployment Verification Checklist

Execute these smoke-tests against your live deployed endpoints:

- [ ] **Health Endpoint:** `GET https://your-backend.onrender.com/health` returns HTTP 200 with `status: "healthy"` and loaded model flags.
- [ ] **Live UI Loading:** Open `https://your-frontend.vercel.app`. Verify that the top-right status pill displays `Backend API Online` (green).
- [ ] **Benign Smoke-Test:** Click the `Benign` demo preset. Verify a fast `BENIGN` response with score $< 30$.
- [ ] **Phishing Smoke-Test:** Click `PayPal Phish` preset. Verify an instant `HIGH-RISK` response with detected manipulation tactics.
- [ ] **Multimodal OCR/Audio Upload:** Test image and audio upload to confirm in-memory processing succeeds without memory allocation errors.
- [ ] **Report Export:** Verify `Copy Summary (MD)` and `Export JSON Report` function cleanly.

---

## 6. Cold Start & Provider Failure Mitigation

1. **Render Free-Tier Spin-Downs:**
   * Render free tier instances spin down after 15 minutes of inactivity. First requests after spin-down may take ~20–40 seconds to awaken.
   * The frontend `Navbar` shows a friendly `Pinging API...` amber state during spin-up.
2. **LLM Provider Outage / Missing Key:**
   * If `GEMINI_API_KEY` is not provided, exhausted, or experiences a timeout ($> 5.0$s), the backend seamlessly falls back to the deterministic rule-grounded briefing with zero service failure.

---

## 7. Rollback Procedures

### Backend Rollback on Render:
1. In the Render Dashboard, navigate to `phishlens-ai-backend` > **Deploys**.
2. Select the previous stable deployment from the deploy history.
3. Click the three dots (`...`) and select **Rollback to this deploy**.
4. Render will instantaneously re-route traffic to the selected build container in $< 10$ seconds.

### Frontend Rollback on Vercel:
1. In the Vercel Dashboard, navigate to your project > **Deployments**.
2. Locate the previous functioning deployment.
3. Click the three dots (`...`) and select **Assign Domain**.
4. Move the production domain to the previous deployment. Rollback takes effect globally in $< 5$ seconds.
