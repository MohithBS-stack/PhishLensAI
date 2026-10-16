# Multimodal Runtime & Model Deployment Guide
## Phase 3: Screenshot OCR & Audio Speech-to-Text Architecture

**Project:** PhishLens AI  
**Event:** CyberForge Hackathon 2026  
**Status:** Phase 3 Implemented & Tested  

---

## 1. Overview & Architectural Boundaries

Phase 3 extends PhishLens AI's threat detection pipeline into visual and spoken media:
1. **Screenshot OCR Analysis:** Ingests images of suspicious SMS conversations, login prompts, and emails, extracting visible text and embedded URLs.
2. **Audio Message Analysis:** Ingests voicemail recordings and spoken alerts, transcribing speech to text and analyzing it for scam patterns.
3. **Passive Threat Evaluation:** Reuses the core `MessageAnalysisService` (Model A text classification + Model B lexical URL classification). Neither service issues outbound HTTP calls or visits extracted URLs.

```
+------------------------------------+      +------------------------------------+
|         Screenshot Upload          |      |            Audio Upload            |
|       (PNG, JPG, JPEG <= 10MB)     |      |       (WAV, MP3, M4A <= 25MB)      |
+-----------------+------------------+      +-----------------+------------------+
                  |                                           |
                  v                                           v
+------------------------------------+      +------------------------------------+
|             OCR Engine             |      |             STT Engine             |
|   (Windows.Media.Ocr / Tesseract)  |      |      (OpenAI-Whisper 'tiny')       |
+-----------------+------------------+      +-----------------+------------------+
                  |                                           |
                  +---------------------+---------------------+
                                        | Extracted Text / Transcript
                                        v
                    +---------------------------------------+
                    |        MessageAnalysisService         |
                    |  - Model A: Spam / Urgency Scoring    |
                    |  - Model B: Passive URL Extraction    |
                    |  - Risk Indicator & Composite Severity|
                    +---------------------------------------+
```

---

## 2. Screenshot OCR Specification

### 2.1 File Ingestion Constraints
- **Allowed Formats:** PNG, JPEG, JPG
- **Maximum File Size:** 10 MB
- **Validation:** Magic bytes checked before processing (`\x89PNG\r\n\x1a\n` for PNG; `\xff\xd8\xff` for JPEG). Non-image files return HTTP 422 `VALIDATION_ERROR`.
- **Memory Safety:** Processed purely in-memory via `PIL.Image.open(io.BytesIO(...))`. Zero disk retention.

### 2.2 OCR Engine Setup & Deployment Requirements
1. **Windows 10/11 Deployment:**
   - Uses `winocr` (`winrt-windows-media-ocr`), utilizing the native OS OCR runtime. Zero external binary installations required.
2. **Linux / Container Deployment (Docker):**
   - Install system Tesseract binary:
     ```bash
     apt-get update && apt-get install -y tesseract-ocr tesseract-ocr-eng
     ```
   - Python wrapper: `pytesseract>=0.3.10`.
3. **Graceful Handling of Blank/Corrupt Images:**
   - If an image contains no readable text, `OCRService` returns an empty string without raising an exception, resulting in a low-risk baseline evaluation.

---

## 3. Audio Speech-to-Text Specification

### 3.1 File Ingestion Constraints
- **Allowed Formats:** WAV, MP3, M4A, OGG, FLAC
- **Maximum File Size:** 25 MB
- **Maximum Duration:** 300 seconds (5 minutes)
- **Validation:** Inspected using `soundfile.info()`. Corrupted files, 0-second files, or files >300s return HTTP 422 `VALIDATION_ERROR`.

### 3.2 Model Integration & Runtime Requirements
- **Pretrained Model:** OpenAI Whisper (`tiny` model, ~39M parameters).
- **Download & Cache:**
  - Whisper automatically downloads model weights on first invocation to `~/.cache/whisper/tiny.pt` (~75 MB).
  - Can be pre-baked into container images via:
    ```bash
    python -c "import whisper; whisper.load_model('tiny')"
    ```
- **Compute Requirements:**
  - CPU: ~1 GB RAM. Inference latency on 10s audio: ~1.2s on modern CPU.
  - GPU (Optional): CUDA acceleration automatically utilized if `torch.cuda.is_available()`.
- **Testing Architecture:**
  - Fast, zero-download synthetic tests are enabled by passing the `x-test-stt-engine: test_stub` header or setting testing mocks.

### 3.3 Safe Temporary File Lifecycle
1. Audio bytes are written to a unique `tempfile.NamedTemporaryFile`.
2. Audio metadata is validated and audio is transcribed.
3. In all execution paths (success or error), the temporary file is unlinked in a `finally:` block. No audio recordings are retained on disk.

---

## 4. Audio Analysis Scope & Voice Cloning Disclaimer

> [!IMPORTANT]
> **Explicit Boundary Disclaimer:**  
> PhishLens AI evaluates text transcripts of spoken messages for social engineering, financial fraud, credential harvesting, and urgency lures.  
> **PhishLens AI DOES NOT analyze voice acoustics, biometric signatures, or claim to detect synthetic speech / AI-generated voice cloning.**

This boundary is explicitly reflected in every API response payload under `disclaimer`:
```json
{
  "disclaimer": "PhishLens AI performs text-based scam and threat analysis on transcribed speech. It does not detect synthetic voices, voice cloning, or deepfakes."
}
```
