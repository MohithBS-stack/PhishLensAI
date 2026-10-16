# Dataset Strategy & Preprocessing Specification
## PhishLens AI — Data Strategy, Schemas, & Ingestion Pipeline

**Event:** CyberForge Hackathon 2026  
**Document Status:** Grounded on Actual Workspace Inspection (Phase 1)  

---

## 1. Inventory & Inspection Summary

| Dataset Identifier | Actual Local Path | Format | Size | Total Rows | Target Column | Distribution | Missing Values |
|---|---|---|---|---|---|---|---|
| **SMS Spam Collection** | `datasets/raw/sms_spam/SMSSpamCollection` | Tab-separated text (no extension) | 477,907 bytes (~466.7 KB) | 5,574 | Label (column 0) | `ham`: 4,827 (86.6%)<br>`spam`: 747 (13.4%) | 0 |
| **PhiUSIIL Phishing URL** | `datasets/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv` | Comma-Separated Values (CSV) | 56,854,345 bytes (~54.22 MB) | 235,795 | `label` (column 55) | `1` (Legitimate): 134,850 (57.19%)<br>`0` (Phishing): 100,945 (42.81%) | 0 (Across all 56 cols) |

### Missing File Notice:
- `datasets/README.md` was referenced in initial documentation but is not present on disk. An informative `datasets/README.md` will be placed in `datasets/` to clearly describe the dataset layout and provenance.
- `datasets/raw/phishing_urls/` exists as an empty directory and will serve as an optional ingestion drop zone for supplementary URL feeds if needed in later phases.

---

## 2. Dataset 1: SMS Spam Collection Deep-Dive

### 2.1 File Characteristics
- **Path:** `datasets/raw/sms_spam/SMSSpamCollection`
- **Encoding:** UTF-8 compatible plain text.
- **Delimiter:** Tab character (`\t`).
- **Structure:** Two fields per row: `<label>\t<message_text>`.
- **Accompanying Documentation:** `datasets/raw/sms_spam/readme` contains compilation details by Tiago A. Almeida and José María Gómez Hidalgo.

### 2.2 Schema & Distribution
- **Target Classes:**
  - `ham`: 4,827 messages (benign user communications, personal messages).
  - `spam`: 747 messages (promotions, unsolicited offers, urgent call-to-actions, lottery lures, smishing links).
- **Imbalance Ratio:** ~6.46:1 (ham to spam). Stratified sampling and class weighting (`class_weight='balanced'`) will be applied during training.

### 2.3 Preprocessing Pipeline (Phase 2 Strategy)
1. **Cleaning:**
   - Case folding (lowercasing).
   - Regex replacement of URLs to a `<URL>` token.
   - Regex replacement of phone numbers to `<PHONE>` token.
   - Regex replacement of currency amounts to `<CURRENCY>` token.
2. **Feature Extraction:**
   - TF-IDF Vectorizer with `ngram_range=(1, 2)`, `min_df=2`, `max_features=5000`.
   - Heuristic metadata features: message length, uppercase character ratio, digit count, exclamation mark frequency.
3. **Train / Validation / Test Split:**
   - 80% Train (4,459 samples), 10% Validation (557 samples), 10% Test (558 samples) with stratified split.

---

## 3. Dataset 2: PhiUSIIL Phishing URL Dataset Deep-Dive

### 3.1 File Characteristics
- **Path:** `datasets/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv`
- **Source:** University of Sharjah & University of Information Technology and Sciences (UCI ML Repository, Prasad & Chandra, 2023).
- **Structure:** 56 columns (54 extracted features + identifier columns + ground truth).
- **Quality Check:** Exactly 0 NaN or null values across all 235,795 rows.

### 3.2 Target Column & Label Encoding
- **Target Column Name:** `label` (int64).
- **Label Mapping:**
  - `label = 1`: **Legitimate** website (134,850 rows, 57.19%).
  - `label = 0`: **Phishing** website (100,945 rows, 42.81%).
- **Important Engineering Rule:** In security systems, a threat score should represent the probability of being malicious. In the PhishLens inference engine, the phishing probability is calculated as `P(phishing) = 1 - P(label == 1)` or explicitly re-mapped such that `1 = Phishing` and `0 = Legitimate` for the internal risk calculation.

### 3.3 Feature Breakdown & Real-Time Extraction Strategy
The PhiUSIIL dataset includes 56 columns:
1. **Identity & Raw Columns:** `FILENAME`, `URL`, `Domain`, `TLD`, `Title`.
2. **Lexical / URL Structure Features (Extractable on-the-fly without live web requests):**
   - `URLLength`, `DomainLength`, `TLDLength`, `NoOfSubDomain`
   - `IsDomainIP`, `IsHTTPS`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`
   - `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`
   - `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`
   - `CharContinuationRate`, `URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb`
3. **Content / HTML Structure Features (Requires rendering HTML):**
   - `LineOfCode`, `LargestLineLength`, `HasTitle`, `HasFavicon`, `Robots`, `IsResponsive`
   - `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`
   - `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

### 3.4 Dual-Tier ML Model Architecture for Inference
To satisfy hackathon latency constraints (<100ms) without risking live network timeout during evaluation:
- **Tier 1 (Lexical Fast-Path - Real-Time):** A lightweight LightGBM model trained exclusively on the 25+ lexical and URL structure features that can be extracted in <2ms from a raw URL string without sending outbound HTTP requests.
- **Tier 2 (Full-Spectrum - Deep Inspection):** For offline batch analysis or deep scan mode where the backend can safely inspect page headers and DOM elements.

---

## 4. Preservation & Data Governance

1. **Read-Only Raw Policy:** Raw dataset files under `datasets/raw/` are treated as immutable ground truth. No script or process may edit, move, or overwrite these files.
2. **Processed Outputs:** Any transformed feature matrices, standardized CSVs, or train/test splits are saved strictly in `datasets/processed/`.
3. **Repository Cleanliness:** All files in `datasets/raw/` and `datasets/processed/` are explicitly ignored by `.gitignore` to prevent bloating the Git tree.
