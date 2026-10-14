"""
Unit tests for Before-and-After Assessment Comparison Service.
"""

import pytest
from extensions import db
from models import Assessment, VulnerabilityFinding
from services.comparison import compare_assessments
from services.deduplication import generate_finding_fingerprint


def test_comparison_calculation(app):
    """Test full comparison metrics including risk reduction and resolved items."""
    with app.app_context():
        # Baseline
        base = Assessment(name="Base", target_url="https://target.local", tester="Analyst", status="Completed")
        retest = Assessment(name="Retest", target_url="https://target.local", tester="Analyst", status="In Progress")
        db.session.add_all([base, retest])
        db.session.commit()

        fp1 = generate_finding_fingerprint("SQLi", "https://target.local/item", "GET", "id", "CWE-89")
        fp2 = generate_finding_fingerprint("XSS", "https://target.local/search", "GET", "q", "CWE-79")

        # Baseline findings: 2 items (Risk: 80 and 60)
        f1_base = VulnerabilityFinding(
            assessment_id=base.id, title="SQLi", affected_url="https://target.local/item",
            http_method="GET", parameter="id", description="Desc", severity="Critical",
            owasp_category="A05:2025 — Injection", risk_score=80.0, remediation_status="Open",
            fingerprint_hash=fp1
        )
        f2_base = VulnerabilityFinding(
            assessment_id=base.id, title="XSS", affected_url="https://target.local/search",
            http_method="GET", parameter="q", description="Desc", severity="High",
            owasp_category="A05:2025 — Injection", risk_score=60.0, remediation_status="Open",
            fingerprint_hash=fp2
        )
        db.session.add_all([f1_base, f2_base])

        # Retest findings: SQLi is Fixed, XSS is still Open, and 1 new finding
        fp_new = generate_finding_fingerprint("New CORS", "https://target.local/api", "GET", None, None)
        f1_retest = VulnerabilityFinding(
            assessment_id=retest.id, title="SQLi", affected_url="https://target.local/item",
            http_method="GET", parameter="id", description="Desc", severity="Critical",
            owasp_category="A05:2025 — Injection", risk_score=80.0, remediation_status="Fixed",
            retest_result="Passed / Remediated", fingerprint_hash=fp1
        )
        f2_retest = VulnerabilityFinding(
            assessment_id=retest.id, title="XSS", affected_url="https://target.local/search",
            http_method="GET", parameter="q", description="Desc", severity="High",
            owasp_category="A05:2025 — Injection", risk_score=60.0, remediation_status="Open",
            fingerprint_hash=fp2
        )
        f_new = VulnerabilityFinding(
            assessment_id=retest.id, title="New CORS", affected_url="https://target.local/api",
            http_method="GET", description="Desc", severity="Medium",
            owasp_category="A01:2025 — Broken Access Control", risk_score=40.0, remediation_status="Open",
            fingerprint_hash=fp_new
        )
        db.session.add_all([f1_retest, f2_retest, f_new])
        db.session.commit()

        # Run comparison
        res = compare_assessments(base.id, retest.id)

        # Baseline open risk: 80 + 60 = 140.0
        # Retest open risk: 60 + 40 = 100.0 (f1 is fixed)
        assert res['baseline']['aggregate_risk'] == 140.0
        assert res['retest']['aggregate_risk'] == 100.0
        assert res['metrics']['fixed_count'] == 1
        assert res['metrics']['persisting_count'] == 1
        assert res['metrics']['new_count'] == 1
        # Risk reduction: (140 - 100) / 140 = 28.57%
        assert res['metrics']['risk_reduction_pct'] == 28.57


def test_zero_baseline_division_safety(app):
    """Ensure zero findings in baseline does not cause ZeroDivisionError."""
    with app.app_context():
        base = Assessment(name="Empty Base", target_url="https://target.local", tester="Tester")
        retest = Assessment(name="Retest", target_url="https://target.local", tester="Tester")
        db.session.add_all([base, retest])
        db.session.commit()

        res = compare_assessments(base.id, retest.id)
        assert res['metrics']['findings_reduction_pct'] == 0.0
        assert res['metrics']['risk_reduction_pct'] == 0.0
