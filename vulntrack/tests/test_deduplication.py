"""
Unit tests for Deduplication and Fingerprint Service.
"""

from services.deduplication import (
    normalize_url,
    normalize_title,
    generate_finding_fingerprint
)


def test_url_normalization():
    """Verify URL scheme/host casing, query sorting, and trailing slashes."""
    url1 = "HTTP://EXAMPLE.COM:8080/path/to/api/?b=2&a=1#section"
    url2 = "http://example.com:8080/path/to/api?a=1&b=2"
    assert normalize_url(url1) == normalize_url(url2)

    # Missing scheme prepends http
    assert normalize_url("target.local/test") == "http://target.local/test"


def test_title_normalization():
    """Verify title punctuation and case stripping."""
    assert normalize_title("SQL Injection (Blind)") == "sql injection blind"
    assert normalize_title("  Cross-Site   Scripting!  ") == "cross site scripting"


def test_fingerprint_matching_and_differentiation():
    """Verify identical items match and different parameters generate distinct hashes."""
    fp1 = generate_finding_fingerprint(
        title="SQL Injection",
        affected_url="https://target.local/search?q=1",
        http_method="GET",
        parameter="q",
        cwe_id="CWE-89"
    )

    # Identical with uppercase scheme / trailing slash
    fp2 = generate_finding_fingerprint(
        title="sql injection",
        affected_url="HTTPS://TARGET.LOCAL/search/?q=1",
        http_method="get",
        parameter="Q",
        cwe_id="cwe-89"
    )
    assert fp1 == fp2

    # Different parameter -> Different fingerprint
    fp_diff = generate_finding_fingerprint(
        title="SQL Injection",
        affected_url="https://target.local/search?q=1",
        http_method="GET",
        parameter="category",
        cwe_id="CWE-89"
    )
    assert fp1 != fp_diff
