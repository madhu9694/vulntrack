"""
VulnTrack OWASP Top 10:2025 Taxonomy and Rule-Based Mapping Service.

Provides category definitions and heuristic classification rules to suggest
the appropriate OWASP Top 10:2025 category based on CWE IDs, vulnerability titles,
and alert descriptions.
"""

import re
from typing import Dict, List, Optional, Tuple, Any

OWASP_2025_CATEGORIES = [
    "A01:2025 — Broken Access Control",
    "A02:2025 — Security Misconfiguration",
    "A03:2025 — Software Supply Chain Failures",
    "A04:2025 — Cryptographic Failures",
    "A05:2025 — Injection",
    "A06:2025 — Insecure Design",
    "A07:2025 — Authentication Failures",
    "A08:2025 — Software or Data Integrity Failures",
    "A09:2025 — Security Logging and Alerting Failures",
    "A10:2025 — Mishandling of Exceptional Conditions",
    "Unclassified / General Security Issue"
]

# CWE to OWASP 2025 direct mapping table
CWE_MAPPING_RULES: Dict[str, str] = {
    # A01: Broken Access Control
    "CWE-22": "A01:2025 — Broken Access Control",    # Path Traversal
    "CWE-23": "A01:2025 — Broken Access Control",
    "CWE-284": "A01:2025 — Broken Access Control",   # Improper Access Control
    "CWE-285": "A01:2025 — Broken Access Control",   # Improper Authorization
    "CWE-639": "A01:2025 — Broken Access Control",   # IDOR
    "CWE-862": "A01:2025 — Broken Access Control",   # Missing Authorization
    "CWE-863": "A01:2025 — Broken Access Control",   # Incorrect Authorization
    "CWE-918": "A01:2025 — Broken Access Control",   # SSRF

    # A02: Security Misconfiguration
    "CWE-16": "A02:2025 — Security Misconfiguration",
    "CWE-200": "A02:2025 — Security Misconfiguration",  # Information Exposure
    "CWE-548": "A02:2025 — Security Misconfiguration",  # Directory Listing
    "CWE-693": "A02:2025 — Security Misconfiguration",  # Protection Mechanism Failure (Headers)
    "CWE-1004": "A02:2025 — Security Misconfiguration", # Sensitive Cookie Without 'HttpOnly'
    "CWE-614": "A02:2025 — Security Misconfiguration",  # Sensitive Cookie in HTTPS Without 'Secure'
    "CWE-1021": "A02:2025 — Security Misconfiguration", # Anti-clickjacking Header Missing

    # A03: Software Supply Chain Failures
    "CWE-1104": "A03:2025 — Software Supply Chain Failures", # Use of Unmaintained 3rd Party Component
    "CWE-1395": "A03:2025 — Software Supply Chain Failures", # Vulnerable Third-Party Library

    # A04: Cryptographic Failures
    "CWE-259": "A04:2025 — Cryptographic Failures",   # Hard-coded Password
    "CWE-326": "A04:2025 — Cryptographic Failures",   # Inadequate Encryption Strength
    "CWE-327": "A04:2025 — Cryptographic Failures",   # Broken/Risky Crypto Algorithm
    "CWE-319": "A04:2025 — Cryptographic Failures",   # Cleartext Transmission
    "CWE-311": "A04:2025 — Cryptographic Failures",   # Missing Encryption

    # A05: Injection
    "CWE-79": "A05:2025 — Injection",                 # Cross-Site Scripting (XSS)
    "CWE-89": "A05:2025 — Injection",                 # SQL Injection
    "CWE-77": "A05:2025 — Injection",                 # Command Injection
    "CWE-78": "A05:2025 — Injection",                 # OS Command Injection
    "CWE-90": "A05:2025 — Injection",                 # LDAP Injection
    "CWE-91": "A05:2025 — Injection",                 # XML Injection
    "CWE-94": "A05:2025 — Injection",                 # Code Injection
    "CWE-643": "A05:2025 — Injection",                # XPath Injection

    # A06: Insecure Design
    "CWE-209": "A06:2025 — Insecure Design",          # Error Message Information Leak
    "CWE-256": "A06:2025 — Insecure Design",          # Unprotected Storage of Credentials
    "CWE-522": "A06:2025 — Insecure Design",          # Insufficiently Protected Credentials
    "CWE-656": "A06:2025 — Insecure Design",          # Reliance on Security Through Obscurity

    # A07: Authentication Failures
    "CWE-287": "A07:2025 — Authentication Failures",  # Improper Authentication
    "CWE-384": "A07:2025 — Authentication Failures",  # Session Fixation
    "CWE-307": "A07:2025 — Authentication Failures",  # Improper Restriction of Excessive Auth Attempts
    "CWE-613": "A07:2025 — Authentication Failures",  # Insufficient Session Expiration
    "CWE-798": "A07:2025 — Authentication Failures",  # Use of Hard-coded Credentials

    # A08: Software or Data Integrity Failures
    "CWE-345": "A08:2025 — Software or Data Integrity Failures", # Insufficient Verification of Data Authenticity
    "CWE-494": "A08:2025 — Software or Data Integrity Failures", # Download of Code Without Integrity Check
    "CWE-502": "A08:2025 — Software or Data Integrity Failures", # Deserialization of Untrusted Data

    # A09: Security Logging and Alerting Failures
    "CWE-778": "A09:2025 — Security Logging and Alerting Failures", # Insufficient Logging
    "CWE-117": "A09:2025 — Security Logging and Alerting Failures", # Improper Output Neutralization for Logs

    # A10: Mishandling of Exceptional Conditions
    "CWE-754": "A10:2025 — Mishandling of Exceptional Conditions", # Improper Check for Unusual Conditions
    "CWE-755": "A10:2025 — Mishandling of Exceptional Conditions", # Improper Handling of Exceptional Conditions
    "CWE-703": "A10:2025 — Mishandling of Exceptional Conditions"  # Improper Check or Handling of Exceptional Conditions
}

# Regex / Keyword rules based on Title & Description
KEYWORD_MAPPING_RULES: List[Tuple[re.Pattern, str, str]] = [
    # A05: Injection
    (re.compile(r'\b(sql injection|sqli|blind sql)\b', re.IGNORECASE), "A05:2025 — Injection", "SQL Injection keyword match"),
    (re.compile(r'\b(cross[- ]site scripting|xss|script tag|dom xss|reflected xss|stored xss)\b', re.IGNORECASE), "A05:2025 — Injection", "XSS keyword match"),
    (re.compile(r'\b(command injection|rce|remote code execution|os command)\b', re.IGNORECASE), "A05:2025 — Injection", "Command execution match"),
    (re.compile(r'\b(ldap injection|xpath injection|xml injection|template injection|ssti)\b', re.IGNORECASE), "A05:2025 — Injection", "Injection keyword match"),
    
    # A01: Broken Access Control
    (re.compile(r'\b(path traversal|directory traversal|lfi|local file inclusion|remote file inclusion|rfi)\b', re.IGNORECASE), "A01:2025 — Broken Access Control", "Traversal match"),
    (re.compile(r'\b(idor|insecure direct object reference|broken access control|privilege escalation|unauthorized access|bypassed authorization)\b', re.IGNORECASE), "A01:2025 — Broken Access Control", "Access control keyword match"),
    (re.compile(r'\b(ssrf|server[- ]side request forgery)\b', re.IGNORECASE), "A01:2025 — Broken Access Control", "SSRF keyword match"),
    (re.compile(r'\b(cors|cross[- ]origin resource sharing misconfiguration)\b', re.IGNORECASE), "A01:2025 — Broken Access Control", "CORS access control match"),

    # A07: Authentication Failures
    (re.compile(r'\b(brute force|session fixation|credential stuffing|password guessing|weak password|session expiration|missing mfa|jwt invalid|broken authentication)\b', re.IGNORECASE), "A07:2025 — Authentication Failures", "Authentication keyword match"),

    # A04: Cryptographic Failures
    (re.compile(r'\b(cleartext|plaintext|ssl|tls|weak cipher|insecure cryptographic|md5|sha[- ]?1|hardcoded key|private key|sensitive data exposure in transit)\b', re.IGNORECASE), "A04:2025 — Cryptographic Failures", "Cryptography match"),

    # A02: Security Misconfiguration
    (re.compile(r'\b(content[- ]security[- ]policy|csp|x[- ]frame[- ]options|strict[- ]transport[- ]security|hsts|cookie.*httponly|cookie.*secure|server banner|directory listing|debug mode|default credentials|header missing)\b', re.IGNORECASE), "A02:2025 — Security Misconfiguration", "Misconfiguration match"),

    # A03: Software Supply Chain Failures
    (re.compile(r'\b(vulnerable component|outdated library|outdated version|dependency|supply chain|cve[- ]\d{4})\b', re.IGNORECASE), "A03:2025 — Software Supply Chain Failures", "Supply chain / dependency match"),

    # A08: Software or Data Integrity Failures
    (re.compile(r'\b(deserialization|insecure deserialization|pickle|object injection|subresource integrity|sri missing)\b', re.IGNORECASE), "A08:2025 — Software or Data Integrity Failures", "Integrity match"),

    # A09: Security Logging and Alerting Failures
    (re.compile(r'\b(insufficient logging|missing audit|log injection|unlogged exception|log poisoning)\b', re.IGNORECASE), "A09:2025 — Security Logging and Alerting Failures", "Logging match"),

    # A10: Mishandling of Exceptional Conditions
    (re.compile(r'\b(unhandled exception|stack trace|null pointer|uncaught error|resource exhaustion|denial of service|dos)\b', re.IGNORECASE), "A10:2025 — Mishandling of Exceptional Conditions", "Exception handling match")
]


def suggest_owasp_category(
    title: str,
    description: str = "",
    cwe_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Suggest an OWASP Top 10:2025 category based on CWE ID, title, and description.
    
    Returns:
        dict: {
            'category': str,
            'confidence': 'High' | 'Medium' | 'Low' | 'Uncertain',
            'matched_rule': str,
            'is_suggestion': True,
            'taxonomy_version': '2025'
        }
    """
    # VIVA NOTE: Why this hierarchy?
    # 1. CWE is the most reliable industry standard; if ZAP or Burp provides a CWE, we trust that first.
    # 2. If CWE is missing, we use regex keywords on the title and description.
    # 3. If evidence is ambiguous, we flag it as 'Uncertain' so the tester can review and override manually.
    if cwe_id:
        norm_cwe = cwe_id.strip().upper()
        if not norm_cwe.startswith("CWE-"):
            digits = re.findall(r'\d+', norm_cwe)
            if digits:
                norm_cwe = f"CWE-{digits[0]}"
        
        if norm_cwe in CWE_MAPPING_RULES:
            return {
                'category': CWE_MAPPING_RULES[norm_cwe],
                'confidence': 'High',
                'matched_rule': f"Direct mapping from {norm_cwe}",
                'is_suggestion': True,
                'taxonomy_version': '2025'
            }

    combined_text = f"{title} {description}"

    # 2. Check keyword and regex patterns in title and description
    for pattern, category, rule_desc in KEYWORD_MAPPING_RULES:
        if pattern.search(title):
            return {
                'category': category,
                'confidence': 'High',
                'matched_rule': f"Title pattern: {rule_desc}",
                'is_suggestion': True,
                'taxonomy_version': '2025'
            }
        elif pattern.search(combined_text):
            return {
                'category': category,
                'confidence': 'Medium',
                'matched_rule': f"Context pattern: {rule_desc}",
                'is_suggestion': True,
                'taxonomy_version': '2025'
            }

    # 3. Fallback when evidence is insufficient
    return {
        'category': "Unclassified / General Security Issue",
        'confidence': 'Uncertain',
        'matched_rule': "No deterministic CWE or pattern matched; requires tester classification.",
        'is_suggestion': True,
        'taxonomy_version': '2025'
    }
