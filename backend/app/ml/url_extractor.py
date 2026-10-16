"""URL Lexical Feature Extractor for PhishLens AI.

Extracts on-the-fly lexical and structural features directly from a submitted URL string
without requiring live network connections, external lookups, or HTML rendering.
"""
from typing import Dict, List, Any, Union
import re
import urllib.parse
import ipaddress
import numpy as np


# Exact ordered list of features used in the URL-only model
URL_FEATURE_NAMES: List[str] = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


def extract_url_features_dict(raw_url: str) -> Dict[str, Union[int, float]]:
    """Extracts lexical feature dictionary from a raw URL string matching the PhiUSIIL schema.
    
    Args:
        raw_url: The URL string to analyze.
        
    Returns:
        Dict mapping each feature name to its numerical value.
    """
    url_str = str(raw_url).strip()
    if not url_str:
        return {feat: 0 for feat in URL_FEATURE_NAMES}

    # Protocol detection
    is_https = 1 if url_str.lower().startswith("https://") else 0

    # Clean URL for body character counts (mirrors PhiUSIIL protocol: strips scheme & leading www)
    clean_url = re.sub(r"^https?://(www\.)?", "", url_str, flags=re.IGNORECASE)

    # Domain parsing
    parsed = urllib.parse.urlparse(url_str if "://" in url_str else f"http://{url_str}")
    domain = parsed.netloc or clean_url.split("/")[0]
    domain_clean = domain.split(":")[0]  # strip port if present

    # Is Domain an IP address?
    is_ip = 0
    try:
        ipaddress.ip_address(domain_clean)
        is_ip = 1
    except ValueError:
        is_ip = 0

    url_length = len(url_str)
    domain_length = len(domain_clean)

    # TLD and subdomains
    domain_parts = domain_clean.split(".")
    if len(domain_parts) > 1 and is_ip == 0:
        tld = domain_parts[-1]
        tld_length = len(tld)
        # e.g., auth.portal.bank.com -> 2 subdomains
        no_subdomain = max(0, len(domain_parts) - 2)
    else:
        tld = ""
        tld_length = 0
        no_subdomain = 0

    # Obfuscation (percent-encoded characters, e.g. %20, %2F)
    obf_matches = re.findall(r"%[0-9a-fA-F]{2}", url_str)
    no_obfuscated = len(obf_matches) * 3
    has_obfuscation = 1 if no_obfuscated > 0 else 0
    obfuscation_ratio = no_obfuscated / max(url_length, 1)

    # Body characters (letters, digits, special characters)
    # PhiUSIIL counts letters in the clean body (clean_url minus scheme/www)
    letters = max(0, len(re.findall(r"[a-zA-Z]", clean_url)) - 1)
    letter_ratio = letters / max(url_length, 1)

    digits = len(re.findall(r"[0-9]", clean_url))
    digit_ratio = digits / max(url_length, 1)

    no_equals = url_str.count("=")
    no_qmark = url_str.count("?")
    no_amp = url_str.count("&")

    # Other special characters
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", clean_url))
    special_char_ratio = special_chars / max(url_length, 1)

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated,
        "ObfuscationRatio": round(obfuscation_ratio, 5),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letter_ratio, 5),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digit_ratio, 5),
        "NoOfEqualsInURL": no_equals,
        "NoOfQMarkInURL": no_qmark,
        "NoOfAmpersandInURL": no_amp,
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": round(special_char_ratio, 5),
        "IsHTTPS": is_https,
    }


def extract_url_feature_vector(raw_url: str) -> np.ndarray:
    """Extracts ordered feature vector as 1D numpy array."""
    feat_dict = extract_url_features_dict(raw_url)
    return np.array([feat_dict[name] for name in URL_FEATURE_NAMES], dtype=float)


def extract_batch_url_features(urls: List[str]) -> np.ndarray:
    """Extracts 2D numpy array of feature vectors for a list of URLs."""
    return np.vstack([extract_url_feature_vector(u) for u in urls])
