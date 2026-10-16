"""Evidence-Backed Manipulation and Social Engineering Tactic Detector.

Implements rules for:
- Urgency and artificial deadlines
- Authority impersonation claims
- Secrecy and discouraging verification
- Credential and OTP requests
- Suspicious payment requests
- Suspicious URLs and identity inconsistencies

Every finding contains an exact supporting excerpt.
These indicators reflect psychological manipulation techniques and are not definitive proof of malicious intent by themselves.
"""
from typing import List, Tuple, Dict, Any, Optional
import re
from urllib.parse import urlparse
import uuid

from app.schemas.evidence import ManipulationTactic, NormalizedEvidence

# Brand to legitimate official registered domains mapping
BRAND_DOMAIN_MAPPING = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "google": ["google.com", "gmail.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "usps": ["usps.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk"],
}

URGENCY_RULES = [
    (
        r"(?i)\b(?:urgent|immediately|act now|hurry|asap|within \d+ (?:hours?|minutes?|days?)|right away|instantly)\b",
        "Urgency & Immediate Action Trigger",
        "high",
        "Pressures the recipient to act impulsively without verifying legitimacy via official channels.",
    ),
    (
        r"(?i)\b(?:expires? (?:today|soon|in \d+)|final notice|last chance|time[- ]sensitive|limited time|strict deadline)\b",
        "Artificial Deadline Pressure",
        "medium",
        "Creates artificial scarcity or time constraint to discourage deliberate reflection.",
    ),
    (
        r"(?i)\b(?:account (?:will be |is )?(?:suspended|terminated|deactivated|closed|deleted|restricted|frozen|locked)(?: in \d+ (?:hours?|minutes?|days?)| today| immediately)?)\b",
        "Account Suspension Scare",
        "high",
        "Threatens catastrophic account lockout to trigger panic and hasty compliance.",
    ),
]

AUTHORITY_RULES = [
    (
        r"(?i)\b(?:irs|internal revenue service|hmrc|tax refund|federal police|fbi|interpol|department of justice|law enforcement|court notice|sheriff|subpoena|customs and border)\b",
        "Government / Law Enforcement Impersonation",
        "high",
        "Claims legal authority or punitive government consequences to compel obedience.",
    ),
    (
        r"(?i)\b(?:paypal|chase bank|wells fargo|bank of america|citibank|capital one|barclays|hsbc|santander|td bank|fraud prevention department|security team)\b",
        "Financial Institution Impersonation",
        "high",
        "Poses as a trusted banking entity to gain credibility regarding account or transaction alerts.",
    ),
    (
        r"(?i)\b(?:microsoft support|apple support|icloud security|google security team|amazon customer service|netflix billing|geek squad|att support|verizon wireless)\b",
        "Tech Support / Service Provider Impersonation",
        "medium",
        "Mimics global consumer tech platforms to simulate legitimate service communications.",
    ),
    (
        r"(?i)\b(?:usps tracking|fedex delivery|ups package|dhl express|postal service delivery failure)\b",
        "Postal / Parcel Delivery Impersonation",
        "medium",
        "Impersonates package logistics services commonly exploited in delivery smishing campaigns.",
    ),
]

SECRECY_RULES = [
    (
        r"(?i)\b(?:do not (?:tell|inform|share with|disclose to|contact) (?:anyone|your bank|family|friends|police|customer support|it department))\b",
        "Active Isolation / Verification Discouragement",
        "critical",
        "Explicitly forbids consulting trusted individuals, institutions, or official helpdesks.",
    ),
    (
        r"(?i)\b(?:keep this (?:strictly )?(?:confidential|secret|private)|between (?:you and me|us)|do not call (?:the )?(?:bank|support|number))\b",
        "Secrecy Demand",
        "high",
        "Demands non-disclosure to prevent the target from validating claims with external advisors.",
    ),
    (
        r"(?i)\b(?:bypass (?:your )?security|ignore (?:the )?warnings?|silently confirm)\b",
        "Security Bypass Solicitation",
        "high",
        "Instructs the recipient to ignore automated warning dialogues or security procedures.",
    ),
]

CREDENTIAL_RULES = [
    (
        r"(?i)\b(?:(?:enter|provide|send|verify|confirm|input|type) (?:your )?(?:password|passcode|pin|otp|one[- ]time (?:password|code|pin)|2fa|two[- ]factor|verification code|security code|security questions?))\b",
        "Credential / OTP Harvesting Lure",
        "critical",
        "Solicits authentication secrets or one-time codes that compromise account integrity.",
    ),
    (
        r"(?i)\b(?:social security number|ssn|login credentials|card details|cvv|cvc|expiration date)\b",
        "High-Value PII / Financial Secret Request",
        "critical",
        "Requests irreversible personal identity identifiers or payment card verification values.",
    ),
    (
        r"(?i)\b(?:update your login|reset your password here|confirm your identity to regain access|log in to verify)\b",
        "Identity Verification Trap",
        "high",
        "Lures target into submitting authentication tokens under the guise of account verification.",
    ),
]

PAYMENT_RULES = [
    (
        r"(?i)\b(?:(?:buy|purchase|pay with) (?:steam|apple|itunes|amazon|google play)? ?gift cards?)\b",
        "Gift Card Payment Demand",
        "critical",
        "Demands retail gift cards as payment, an untraceable and non-refundable scam hallmark.",
    ),
    (
        r"(?i)\b(?:bitcoin|btc|crypto(?:currency)?|ethereum|eth|usdt|tether|wallet address)\b",
        "Cryptocurrency Payment Rail",
        "high",
        "Directs funds to irreversible, pseudonymous decentralized crypto wallets.",
    ),
    (
        r"(?i)\b(?:wire transfer|western union|moneygram|cashapp|cash app|venmo|zelle)\b",
        "Irreversible P2P / Wire Transfer Cue",
        "medium",
        "Directs payments through consumer peer-to-peer or remittance rails without buyer protection.",
    ),
    (
        r"(?i)\b(?:pay (?:an? )?(?:advance|processing|release|unclaimed|clearance|courier) fee)\b",
        "Advance Fee / Clearance Lure",
        "high",
        "Demands an upfront fee under the promise of releasing a larger prize, loan, or parcel.",
    ),
]


class ManipulationDetector:
    """Detects evidence-backed social engineering manipulation tactics across text and URLs."""

    @classmethod
    def extract_domain(cls, url: str) -> str:
        """Extracts cleaned hostname/domain from URL string."""
        if not url:
            return ""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host

    @classmethod
    def check_brand_domain_inconsistency(
        cls, text: str, urls: List[str]
    ) -> List[ManipulationTactic]:
        """Detects discrepancies between claimed brand in text and destination URL domains."""
        tactics: List[ManipulationTactic] = []
        if not text or not urls:
            return tactics

        text_lower = text.lower()

        for brand, legitimate_domains in BRAND_DOMAIN_MAPPING.items():
            # Check if brand is mentioned in text with word boundary
            brand_pattern = rf"\b{re.escape(brand)}\b"
            if re.search(brand_pattern, text_lower):
                for url in urls:
                    domain = cls.extract_domain(url)
                    if not domain:
                        continue

                    # Check if domain matches any legitimate domain or is a legit subdomain
                    is_legit = any(
                        domain == legit or domain.endswith("." + legit)
                        for legit in legitimate_domains
                    )

                    if not is_legit:
                        tactics.append(
                            ManipulationTactic(
                                tactic_id=f"tactic-inconsistency-{uuid.uuid4().hex[:8]}",
                                category="identity_inconsistency",
                                name=f"Brand Spoofing & Domain Mismatch ({brand.title()})",
                                description=(
                                    f"Communication claims to represent {brand.title()}, but the destination "
                                    f"URL '{url}' routes to an unverified domain '{domain}' rather than an "
                                    f"official domain ({', '.join(legitimate_domains)})."
                                ),
                                severity="critical",
                                supporting_evidence=f"Claimed brand '{brand.title()}' in message, but link points to '{domain}'",
                            )
                        )

        # Check for numeric IP hostnames or suspicious TLDs in URLs
        suspicious_tlds = {".xyz", ".top", ".tk", ".icu", ".buzz", ".work", ".ml", ".ga", ".cf"}
        ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

        for url in urls:
            domain = cls.extract_domain(url)
            if ip_pattern.match(domain):
                tactics.append(
                    ManipulationTactic(
                        tactic_id=f"tactic-inconsistency-ip-{uuid.uuid4().hex[:8]}",
                        category="identity_inconsistency",
                        name="Raw IP Address URL Destination",
                        description=f"Destination URL '{url}' uses a raw IP address ({domain}) instead of a registered domain name, heavily characteristic of evasion techniques.",
                        severity="high",
                        supporting_evidence=f"Raw IP host: {domain}",
                    )
                )
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    tactics.append(
                        ManipulationTactic(
                            tactic_id=f"tactic-inconsistency-tld-{uuid.uuid4().hex[:8]}",
                            category="identity_inconsistency",
                            name=f"High-Risk TLD Destination ({tld})",
                            description=f"Destination URL '{url}' utilizes top-level domain '{tld}' disproportionately correlated with disposable phishing infrastructure.",
                            severity="medium",
                            supporting_evidence=f"URL with high-risk TLD: {url}",
                        )
                    )

        return tactics

    @classmethod
    def detect_tactics(
        cls,
        text: str,
        urls: Optional[List[str]] = None,
        source_modality: str = "text",
    ) -> Tuple[List[ManipulationTactic], List[NormalizedEvidence]]:
        """Detects all evidence-backed manipulation tactics and returns normalized evidence items."""
        tactics: List[ManipulationTactic] = []
        evidence_items: List[NormalizedEvidence] = []
        cleaned_text = str(text or "").strip()
        url_list = urls or []

        rule_groups = [
            ("urgency", URGENCY_RULES),
            ("authority_impersonation", AUTHORITY_RULES),
            ("secrecy", SECRECY_RULES),
            ("credential_request", CREDENTIAL_RULES),
            ("payment_request", PAYMENT_RULES),
        ]

        seen_excerpts = set()

        if cleaned_text:
            for category, rules in rule_groups:
                for pattern, name, severity, desc in rules:
                    for match in re.finditer(pattern, cleaned_text):
                        excerpt = match.group(0).strip()
                        norm_key = (category, excerpt.lower())
                        if norm_key in seen_excerpts:
                            continue
                        seen_excerpts.add(norm_key)

                        tactic_id = f"tactic-{category[:3]}-{uuid.uuid4().hex[:8]}"
                        tactics.append(
                            ManipulationTactic(
                                tactic_id=tactic_id,
                                category=category,
                                name=name,
                                description=desc,
                                severity=severity,
                                supporting_evidence=excerpt,
                            )
                        )

                        evidence_items.append(
                            NormalizedEvidence(
                                evidence_id=f"ev-{category[:3]}-{uuid.uuid4().hex[:8]}",
                                source_modality=source_modality,
                                indicator_type=f"manipulation_{category}",
                                description=f"{name}: {desc}",
                                supporting_excerpt=excerpt,
                                severity=severity,
                                evidence_source="manipulation_rule_engine",
                                confidence=0.85,
                                observed_versus_inferred="observed",
                                limitations_and_missing_checks=[
                                    "Lexical keyword trigger; contextual semantic intent requires human review.",
                                    "Indicator reflects psychological manipulation patterns and is not proof of malice on its own.",
                                ],
                            )
                        )

        # Check for brand domain inconsistencies
        inconsistency_tactics = cls.check_brand_domain_inconsistency(cleaned_text, url_list)
        for tactic in inconsistency_tactics:
            tactics.append(tactic)
            evidence_items.append(
                NormalizedEvidence(
                    evidence_id=f"ev-incon-{uuid.uuid4().hex[:8]}",
                    source_modality="url",
                    indicator_type="identity_inconsistency",
                    description=tactic.description,
                    supporting_excerpt=tactic.supporting_evidence,
                    severity=tactic.severity,
                    evidence_source="identity_consistency_checker",
                    confidence=0.90,
                    observed_versus_inferred="inferred",
                    limitations_and_missing_checks=[
                        "Compared against static list of well-known brand domains.",
                        "Live DNS, WHOIS creation date, and SSL certificates were not queried.",
                    ],
                )
            )

        return tactics, evidence_items


manipulation_detector = ManipulationDetector()
