"""
VulnTrack Deduplication and Fingerprint Service.

Generates deterministic SHA-256 fingerprints to identify recurring or redundant
findings across different scans or within the same assessment engagement.
Deduplication is a heuristic aid and preserves all records with links to the original.
"""

import hashlib
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import Optional, Dict, Any, List


def normalize_url(url_str: str) -> str:
    """
    Normalize URL by:
    - Lowercasing scheme and netloc (hostname + port)
    - Removing URI fragments (#hash)
    - Sorting query parameters deterministically
    - Stripping trailing slashes in path
    """
    if not url_str:
        return ""
    
    url_clean = url_str.strip()
    if not re.match(r'^[a-zA-Z]+://', url_clean):
        url_clean = 'http://' + url_clean

    parsed = urlparse(url_clean)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip('/') or '/'

    # Sort query parameters
    query_params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_params)

    # Reconstruct normalized URL without fragment
    normalized = urlunparse((scheme, netloc, path, '', query, ''))
    return normalized


def normalize_title(title: str) -> str:
    """Clean vulnerability title for structural comparison."""
    if not title:
        return ""
    # Lowercase, strip punctuation and excessive whitespace
    cleaned = title.strip().lower()
    cleaned = re.sub(r'[^a-z0-9\s]', ' ', cleaned)
    return ' '.join(cleaned.split())


def generate_finding_fingerprint(
    title: str,
    affected_url: str,
    http_method: str = "GET",
    parameter: Optional[str] = None,
    cwe_id: Optional[str] = None
) -> str:
    """
    Generate SHA-256 fingerprint from normalized core fields.
    
    VIVA NOTE: How does our deduplication work?
    In recurring scans, ZAP often reports the exact same issue multiple times.
    To detect this without deleting data:
    1. We normalize URL casing, remove fragments (#section), and sort query parameters.
    2. We include the parameter name so different bugs on the same page don't clash.
    3. We hash everything with SHA-256 to create a unique fingerprint string.
    4. Findings matching an existing fingerprint are flagged as duplicates, linking
       back to the original finding while keeping both in the database.
    """
    norm_title = normalize_title(title)
    norm_url = normalize_url(affected_url)
    norm_method = (http_method or "GET").strip().upper()
    norm_param = (parameter or "").strip().lower()
    norm_cwe = (cwe_id or "").strip().upper()

    seed = f"{norm_title}|{norm_url}|{norm_method}|{norm_param}|{norm_cwe}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()


def find_matching_original(
    fingerprint: str,
    current_assessment_id: Optional[int] = None,
    exclude_finding_id: Optional[int] = None
) -> Optional[Any]:
    """
    Query the database for an existing primary finding with the same fingerprint.
    Prioritizes non-duplicate findings, preferring ones in the same assessment if available.
    """
    from models import VulnerabilityFinding

    query = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.fingerprint_hash == fingerprint,
        VulnerabilityFinding.is_duplicate.is_(False)
    )

    if exclude_finding_id:
        query = query.filter(VulnerabilityFinding.id != exclude_finding_id)

    # Prefer matching within the same assessment first
    if current_assessment_id:
        same_assessment = query.filter_by(assessment_id=current_assessment_id).first()
        if same_assessment:
            return same_assessment

    return query.first()
