# PhiUSIIL Feature Classification & Selection Manifesto

**Dataset:** PhiUSIIL Phishing URL Dataset (56 total columns, 235,795 rows)  
**Task:** Live URL-Only Phishing Detection  

---

## 1. Verified Target Column
- **Column Name:** `label` (int64)
- **Raw Encoding:** `1` = Legitimate (134,850 rows), `0` = Phishing (100,945 rows).
- **PhishLens Target Mapping:** Mapped to binary indicator `is_phishing = (label == 0).astype(int)` to align with cybersecurity convention where class 1 represents detected threats.

---

## 2. Included Features (18 Columns)
All 18 features are extracted purely from the submitted URL string without external network calls:

| Feature Name | Type | Description | Extraction Method |
|---|---|---|---|
| `URLLength` | int | Total length of the URL | `len(url)` |
| `DomainLength` | int | Length of domain string | `len(domain)` |
| `IsDomainIP` | binary | Domain is IPv4 or IPv6 | IP address regex / socket validation |
| `TLDLength` | int | Length of top-level domain | `len(tld)` |
| `NoOfSubDomain` | int | Count of subdomains | Domain parts split count |
| `HasObfuscation` | binary | Presence of percent-encoding (`%XX`) | Regex `r'%[0-9a-fA-F]{2}'` |
| `NoOfObfuscatedChar` | int | Total characters in hex escapes | Count of percent-encoded sequences × 3 |
| `ObfuscationRatio` | float | Ratio of obfuscation chars to URL length | `NoOfObfuscatedChar / URLLength` |
| `NoOfLettersInURL` | int | Alphabetic character count in clean body | Count of `[a-zA-Z]` (minus scheme/www) |
| `LetterRatioInURL` | float | Ratio of letters to URL length | `NoOfLettersInURL / URLLength` |
| `NoOfDegitsInURL` | int | Digit count in clean body | Count of `[0-9]` |
| `DegitRatioInURL` | float | Ratio of digits to URL length | `NoOfDegitsInURL / URLLength` |
| `NoOfEqualsInURL` | int | Count of `=` characters | `url.count('=')` |
| `NoOfQMarkInURL` | int | Count of `?` characters | `url.count('?')` |
| `NoOfAmpersandInURL` | int | Count of `&` characters | `url.count('&')` |
| `NoOfOtherSpecialCharsInURL` | int | Count of special characters | Regex `r'[^a-zA-Z0-9]'` |
| `SpacialCharRatioInURL` | float | Ratio of special chars to URL length | `NoOfOtherSpecialCharsInURL / URLLength` |
| `IsHTTPS` | binary | Protocol is HTTPS | Starts with `https://` |

---

## 3. Excluded Webpage-Derived Features (29 Columns)
These 29 features require making an outbound network request, downloading page content, and executing DOM/CSS/JS parsing:
- `LineOfCode`, `LargestLineLength`
- `HasTitle`, `Title`, `DomainTitleMatchScore`, `URLTitleMatchScore`
- `HasFavicon`, `Robots`, `IsResponsive`
- `NoOfURLRedirect`, `NoOfSelfRedirect`
- `HasDescription`, `NoOfPopup`, `NoOfiFrame`
- `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`
- `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`
- `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

**Exclusion Rationale:**
1. **SSRF Vulnerability:** Outbound HTTP requests can be abused to attack internal cloud metadata services (`169.254.169.254`).
2. **Latency:** Fetching and rendering an external website takes 800ms–5,000ms, violating sub-100ms real-time requirements.
3. **Availability:** Phishing pages are often taken down within hours; models relying on live DOM features fail when the page is inactive.

---

## 4. Excluded Identifiers & Training-Corpus Lookups (8 Columns)
- `FILENAME`: Internal file index; would cause target leakage.
- `URL`, `Domain`, `TLD`: Raw strings; high cardinality, replaced by lexical features.
- `URLSimilarityIndex`: Calculated against Alexa 100k database not included in repository.
- `TLDLegitimateProb`: Empirical probability table from training corpus.
- `URLCharProb`: Language model probabilities from training corpus.
- `CharContinuationRate`: Proprietary tokenizer metric.
