# Security & Threat Model Policy
## PhishLens AI — Security Architecture & Data Handling Guidelines

**Event:** CyberForge Hackathon 2026  
**Document Version:** 1.0.0  

---

## 1. Security Principles & Threat Landscape

PhishLens AI processes potentially malicious, weaponized content (e.g., zero-day phishing links, smishing lures, and obfuscated exploit scripts). In doing so, the platform itself must remain strictly immune to adversarial exploitation.

### Core Security Tenets:
1. **Zero Untrusted Execution:** Untrusted inputs (text, URLs, headers) are parsed purely as inert strings. They are never evaluated via `eval()`, `exec()`, or unescaped shell commands.
2. **SSRF Prevention:** The backend never issues arbitrary, uncontrolled outbound HTTP/TCP requests to user-supplied URLs without strict boundary checks and sandbox isolation.
3. **Safe Model Deserialization:** Avoid arbitrary Python `pickle.loads()` on unverified binaries. Use strictly version-controlled `.joblib` / `onnx` model files from designated internal paths.
4. **Environment Isolation:** Zero hardcoded API keys, JWT secrets, or connection strings. All runtime configuration is strictly loaded through Pydantic BaseSettings and validated at startup.

---

## 2. Threat Modeling & Mitigations

| Threat Vector | Attack Scenario | PhishLens AI Mitigation |
|---|---|---|
| **Server-Side Request Forgery (SSRF)** | Attacker submits `http://169.254.169.254/latest/meta-data/` or internal IPs (`127.0.0.1`, `10.0.0.1`) | Tier 1 analysis is purely lexical/mathematical and performs zero network calls. When deep resolution is enabled, private IP ranges (RFC 1918 & link-local) are strictly rejected before resolution. |
| **Denial of Service (DoS) via ReDoS / Large Payloads** | Attacker sends massive payloads (>10MB text) or crafted regex triggers | Pydantic schemas enforce max text lengths (e.g., 5,000 chars for SMS, 2,048 chars for URLs). Strict timeouts on regex execution. |
| **Cross-Site Scripting (XSS)** | Attacker submits `<script>alert(1)</script>` inside an SMS or URL to execute in the dashboard | Next.js strictly escapes React state outputs. All response payloads are typed JSON with `Content-Type: application/json`. |
| **Model Inversion / Poisoning** | Malicious data introduced into training pipelines | Raw datasets are marked read-only and immutable. Training datasets use fixed seed splits with integrity hashes. |
| **Insecure Deserialization** | Tampered model weights executing arbitrary code | Model loading verifies expected file extensions and model registry signatures. |

---

## 3. Data Protection & Privacy

- **No Logging of Sensitive PII:** Raw messages are inspected in-memory during request lifecycles. Transient loggers log only request IDs, latency, and threat scores, masking credit card numbers, passwords, and phone numbers.
- **Client-Side Cache Safety:** The frontend stores scan histories strictly in the user's local browser session storage; no user telemetry is exported to third-party trackers.
- **CORS Restriction:** API endpoints restrict cross-origin access to explicitly allowed frontend domains defined in `CORS_ORIGINS`.

---

## 4. Secure Development Lifecycle (SDLC)
- **Static Analysis:** Python files are vetted against linter rules and type checks (`mypy`, `ruff`).
- **Dependency Audit:** Regular dependency checks (`pip audit`, `npm audit`) to avoid vulnerable transitive dependencies.
- **Reporting Vulnerabilities:** For any security vulnerabilities identified in this project, report directly to the CyberForge hackathon repository maintainers.
