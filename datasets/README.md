# Datasets Registry & Directory Guide

This directory stores raw and processed datasets utilized by **PhishLens AI**.

## Directory Structure

```
datasets/
├── README.md                           # This guide
├── raw/
│   ├── phiusiil/
│   │   └── PhiUSIIL_Phishing_URL_Dataset.csv
│   ├── sms_spam/
│   │   ├── SMSSpamCollection           # Tab-separated dataset (no file extension)
│   │   └── readme                      # Source documentation by Almeida et al.
│   └── phishing_urls/                  # Drop zone for supplementary feeds
└── processed/                          # Standardized train/val/test splits (gitignored)
```

## Dataset Specifications

### 1. SMS Spam Collection
- **Path:** `datasets/raw/sms_spam/SMSSpamCollection`
- **Format:** Tab-separated text (`label\tmessage`)
- **Total Records:** 5,574 rows
- **Labels:**
  - `ham`: 4,827 rows (86.6%)
  - `spam`: 747 rows (13.4%)
- **Target Task:** SMS / Smishing classification and urgency detection

### 2. PhiUSIIL Phishing URL Dataset
- **Path:** `datasets/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv`
- **Format:** Comma-Separated Values (CSV)
- **Total Records:** 235,795 rows
- **Features:** 56 total columns (54 extracted features + identifiers + label)
- **Missing Values:** 0
- **Labels (`label` column):**
  - `1`: Legitimate websites (134,850 rows, 57.19%)
  - `0`: Phishing websites (100,945 rows, 42.81%)
- **Target Task:** Real-time URL phishing detection and feature attribution

## Integrity Policy
All raw datasets under `raw/` are immutable and must not be edited or deleted. Generated outputs must be written exclusively to `processed/`.
