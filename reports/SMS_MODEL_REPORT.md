# Model A: Message Classifier Evaluation Report

**Model:** TF-IDF (1–2 ngrams, max 5,000 features) + Logistic Regression (`class_weight='balanced'`)  
**Task:** Binary SMS spam / suspicious message baseline classification  
**Dataset:** [`datasets/raw/sms_spam/SMSSpamCollection`](../datasets/raw/sms_spam/SMSSpamCollection) (Almeida et al.)  
**Artifact:** [`models/saved/sms_classifier.joblib`](../models/saved/sms_classifier.joblib)  

---

## 1. Objective & Baseline Characterization
This model serves as a **lightweight, fast baseline** for flagging spam, smishing lures, and unsolicited messages in SMS and chat channels. It operates purely on raw message text without requiring external network lookups or large language models.

---

## 2. Dataset Validation & Splits
- **Total Valid Rows:** 5574
- **Malformed Lines:** 0
- **Class Distribution:** `ham`: 4827, `spam`: 747
- **Split Strategy:** Stratified 80/20 train/test split (`random_state=42`)
- **Train Set Size:** 4459
- **Test Set Size:** 1115

---

## 3. Evaluation Metrics (Held-out Test Split)

| Metric | Score |
|---|---|
| **Accuracy** | 98.4753% |
| **Precision (Spam)** | 94.5946% |
| **Recall (Spam)** | 93.9597% |
| **F1-Score (Spam)** | 94.2761% |

### Confusion Matrix
```
                 Predicted Ham    Predicted Spam
Actual Ham (TN/FP):   958             8
Actual Spam (FN/TP):  9               140
```

### Detailed Classification Report
```
              precision    recall  f1-score   support

         ham       0.99      0.99      0.99       966
        spam       0.95      0.94      0.94       149

    accuracy                           0.98      1115
   macro avg       0.97      0.97      0.97      1115
weighted avg       0.98      0.98      0.98      1115

```

---

## 4. Honest Model Assessment & Caveats
- **Strengths:** Sub-millisecond inference time (<2ms); high recall on classic urgency/lottery/prize spam keywords; low memory footprint.
- **Limitations:** Treats text as bag-of-words / n-grams without deep semantic comprehension; may struggle with adversarial character substitutions (e.g. `P@ypal` or zero-width spaces) unless normalized. Advanced smishing with benign phrasing will be handled in Phase 3 via multi-modal heuristics and URL cross-referencing.
