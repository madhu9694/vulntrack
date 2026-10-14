"""
Unit tests for OWASP Top 10:2025 Taxonomy and Rule Mapper.
"""

from services.owasp_mapper import suggest_owasp_category, OWASP_2025_CATEGORIES


def test_taxonomy_categories():
    """Ensure all 10 OWASP 2025 categories are defined."""
    assert len(OWASP_2025_CATEGORIES) >= 11
    assert any("A01:2025" in cat for cat in OWASP_2025_CATEGORIES)
    assert any("A05:2025" in cat for cat in OWASP_2025_CATEGORIES)
    assert any("A10:2025" in cat for cat in OWASP_2025_CATEGORIES)


def test_cwe_mapping_rules():
    """Verify deterministic CWE mapping."""
    res_sqli = suggest_owasp_category("Database Query Error", cwe_id="CWE-89")
    assert res_sqli['category'] == "A05:2025 — Injection"
    assert res_sqli['confidence'] == 'High'
    assert res_sqli['taxonomy_version'] == '2025'

    res_xss = suggest_owasp_category("Script Reflection", cwe_id="79")
    assert res_xss['category'] == "A05:2025 — Injection"

    res_idor = suggest_owasp_category("Object Reference", cwe_id="CWE-639")
    assert res_idor['category'] == "A01:2025 — Broken Access Control"

    res_supply = suggest_owasp_category("Outdated Component", cwe_id="CWE-1395")
    assert res_supply['category'] == "A03:2025 — Software Supply Chain Failures"


def test_keyword_title_matching():
    """Verify regex and keyword heuristics."""
    res = suggest_owasp_category("Blind SQL Injection on Login Page")
    assert res['category'] == "A05:2025 — Injection"

    res_ssrf = suggest_owasp_category("Server-Side Request Forgery in Webhook")
    assert res_ssrf['category'] == "A01:2025 — Broken Access Control"

    res_auth = suggest_owasp_category("Credential Stuffing Attack Allowed")
    assert res_auth['category'] == "A07:2025 — Authentication Failures"

    res_misc = suggest_owasp_category("X-Frame-Options Header Missing")
    assert res_misc['category'] == "A02:2025 — Security Misconfiguration"


def test_unclassified_fallback():
    """Verify graceful fallback for generic or unclassified issues."""
    res = suggest_owasp_category("Unknown Generic Issue", "No extra details available")
    assert res['category'] == "Unclassified / General Security Issue"
    assert res['confidence'] == 'Uncertain'
