# Model B: Live URL Phishing Classifier Evaluation Report

**Model:** StandardScaler + HistGradientBoostingClassifier (`max_iter=150`, `class_weight='balanced'`)  
**Task:** Live URL Phishing Detection (Lexical URL-only analysis)  
**Dataset:** [`datasets/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv`](../datasets/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv)  
**Artifact:** [`models/saved/url_classifier.joblib`](../models/saved/url_classifier.joblib)  

---

## 1. Feature Strategy: Live URL-Only vs Excluded Features

To ensure **safe, sub-100ms real-time inference** and eliminate SSRF/network risks:
- **Included (18 features):** Strictly features derived mathematically and lexically from the submitted URL string alone.
- **Excluded (29 webpage features):** Webpage content, HTML structure, DOM forms, iframes, and external references are strictly excluded because they require outbound HTTP calls.
- **Excluded (8 other features):** High-cardinality identifiers (`FILENAME`, `URL`, `Domain`, `TLD`) and external lookup metrics (`URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb`, `CharContinuationRate`).

---

## 2. Dataset Distribution & Target Verification
- **Verified Target Column:** `label` (int64)
- **Raw Counts:** `1` (Legitimate): 134,850, `0` (Phishing): 100,945
- **Classification Mapping:** `1 = Phishing` (threat positive), `0 = Legitimate` (benign negative)
- **Total Rows:** 235,795
- **Split Strategy:** Stratified 80/20 train/test split (`random_state=42`)
- **Train Set Size:** 188,636
- **Test Set Size:** 47,159

---

## 3. Evaluation Metrics (Held-out Test Split)

| Metric | Score |
|---|---|
| **Accuracy** | 99.7964% |
| **Precision (Phishing)** | 99.9354% |
| **Recall (Phishing)** | 99.5889% |
| **F1-Score (Phishing)** | 99.7618% |

### Confusion Matrix
```
                         Predicted Legitimate    Predicted Phishing
Actual Legitimate (TN/FP):    26957                   13
Actual Phishing   (FN/TP):    83                      20106
```

### Classification Report
```
              precision    recall  f1-score   support

  Legitimate       1.00      1.00      1.00     26970
    Phishing       1.00      1.00      1.00     20189

    accuracy                           1.00     47159
   macro avg       1.00      1.00      1.00     47159
weighted avg       1.00      1.00      1.00     47159

```

---

## 4. Engineering & Deployment Notes
- **Inference Speed:** Feature extraction + inference executes in <3ms per URL.
- **SSRF Safety:** Complete immunity to SSRF vulnerabilities since no network requests are dispatched to target URLs.
