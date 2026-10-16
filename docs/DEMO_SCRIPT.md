# PhishLens AI — 2-Minute Hackathon Demo Script & Judge Presentation
**Event:** CyberForge Hackathon 2026 | **Time Budget:** 120 Seconds (2:00) | **Target Audience:** Technical Judges & Security Reviewers

---

## ⏱️ Second-by-Second Demo Script

### **[0:00 – 0:25] The Problem & Thesis (25s)**
> *"Good morning, judges. Today’s threat actors don't stay in email. They coordinate multi-vector campaigns across SMS smishing, fake urgency alerts, voice phishing, and disposable zero-day domains that evade static blacklists.*
>
> *Existing tools give you an opaque, uncalibrated score with zero context. We built **PhishLens AI** — a real-time, explainable threat intelligence platform that fuses text, URLs, screenshot OCR, and audio voicemail into unified, evidence-grounded incident reports in under 150 milliseconds."*

### **[0:25 – 0:55] Live Attack Demonstration (30s)**
> *(Action: Click the `PayPal Phish` preset on the dashboard and click `Run Unified Investigation`)*
>
> *"Watch our unified engine in action on an active attack. Here is an SMS claiming to be the PayPal Security Team threatening account suspension in 24 hours with a link to `paypal-verification-center.xyz`.*
>
> *Instantly, our engine synthesizes a **HIGH-RISK (85/100)** verdict. Notice our explainability breakdown:*
> 1. *Our lightweight PhiUSIIL model flagged the URL as phishing based on lexical entropy and domain structure.*
> 2. *Our rule engine flagged an **Identity Inconsistency**: the sender claimed to be PayPal, but the link pointed to an unverified `.xyz` host.*
> 3. *It extracted the exact urgency trigger: 'within 24 hours'."*

### **[0:55 – 1:25] Multimodal Fusion & Edge Resilience (30s)**
> *(Action: Switch to `Full Multimodal` mode, attach sample image/audio, and run investigation)*
>
> *"PhishLens AI doesn't stop at text. Analysts can upload a mobile screenshot or a voicemail audio file.*
> * *Screenshot OCR parses visual text in-memory with zero disk retention.*
> * *Our audio pipeline transcribes voicemail audio into text.*
> * *Crucially: signals are normalized and deduplicated. If the same urgency phrase appears in both the transcript and the screenshot, our **Risk Engine applies correlation dampening** so the score isn't artificially inflated.*
> * *If our Gemini LLM connection is offline or rate-limited, our **deterministic rule generator** guarantees a fully structured briefing with zero service disruption."*

### **[1:25 – 1:45] Measured ML Metrics & Production Rigor (20s)**
> *"Under the hood, we trained on over 240,000 verified samples:*
> * *Our PhiUSIIL URL classifier achieves **99.8% accuracy and a 0.9976 F1-score** using an 18-feature lexical extractor.*
> * *Our SMS spam classifier achieves **98.5% accuracy and a 0.9428 F1-score**.*
> * *Our backend test suite has **43 automated tests passing at 100%**, covering boundary conditions, conflicting signals, and corrupted payloads."*

### **[1:45 – 2:00] Honest Scope, Limitations & Closing (15s)**
> *"We hold ourselves to rigorous security principles: we strictly perform **passive analysis** — we never visit submitted URLs or execute malicious binaries. We also explicitly disclose that model scores are uncalibrated estimates.*
>
> *PhishLens AI empowers everyday consumers and SOC analysts to triage digital deception safely, quickly, and transparently. Thank you!"*

---

## 🎯 Synthetic Demo Scenarios (Zero Real PII)

| Scenario | Input Content | Key Detected Vectors | Expected Verdict & Score |
|---|---|---|---|
| **1. Urgent Smishing + Domain Mismatch** | `URGENT: PayPal Security Alert. Account locked in 24h. Verify at http://paypal-verification-center.xyz` | Urgency Deadline, Authority Claim, Brand Mismatch (`.xyz` TLD) | **HIGH-RISK** (85–95/100) |
| **2. IRS Scam + Secrecy + Gift Card** | `FINAL NOTICE: IRS Lawsuit. Buy Steam gift cards to clear fee. Do not tell your bank.` | Legal Authority Impersonation, Secrecy Demand, Gift Card Payment Rail | **HIGH-RISK** (75–85/100) |
| **3. Clean Benign Message** | `Hey Marcus, here is the draft architecture proposal for review: https://www.southbankmosaics.com` | Verified legitimate domain, conversational ham language | **BENIGN** (0–15/100) |
| **4. Conflicting Signals** | `Hi Mom, having dinner tonight at 7pm: http://paypal-verify-fake.xyz` | Benign greeting text paired with phishing URL destination | **SUSPICIOUS / HIGH-RISK** with Conflicting Signal alert |
| **5. Multimodal Audio + OCR** | Upload voicemail WAV + Screenshot PNG | In-memory OCR text extraction + Audio STT transcription correlation | **FUSED REPORT** across both modalities |

---

## 📊 Measured ML Benchmarks (Phase 2 Serialization)

| Model Name | Training Dataset | Benchmark Size | Features | Test Accuracy | Test F1-Score | Inference Latency |
|---|---|---|---|---|---|---|
| **Model A: SMS Classifier** | SMSSpamCollection | 5,574 messages | TF-IDF (Unigram + Bigram) | **98.48%** | **0.9428** | ~1.8 ms |
| **Model B: URL Classifier** | PhiUSIIL Dataset | 235,795 URLs | 18 Lexical & Structural | **99.80%** | **0.9976** | ~2.1 ms |

---

## 🛡️ Production Safety & Resiliency Architecture

### 1. Cold Start Recovery (Render Free Tier)
* Render free-tier instances sleep after 15 minutes of inactivity.
* The frontend `Navbar` pings `/health` on load with an active pulse indicator.
* If Render is spinning up (20–40s cold start), the frontend shows a polite connecting notice rather than crashing.

### 2. Provider Failure Resiliency (LLM Fallback)
* If `GEMINI_API_KEY` is not configured, expired, or the external API times out ($> 5.0$ seconds), the backend automatically and silently engages the **Deterministic Rule-Grounded Generator**.
* The user receives a complete, structured forensic briefing with zero downtime or 500 errors.

### 3. Untrusted Data Fencing
* User input text and transcripts are wrapped in `<untrusted_user_input>` XML fences before LLM ingestion, with strict system instructions prohibiting prompt injection or instruction overrides.
