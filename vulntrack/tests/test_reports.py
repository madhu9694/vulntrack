"""
Unit tests for ReportLab PDF Report Generator Service.
"""

from services.report_generator import generate_vapt_pdf
from models import VulnerabilityFinding
from extensions import db


def test_pdf_generation_empty_assessment(app, sample_assessment):
    """Verify PDF generates valid byte stream for empty assessment."""
    with app.app_context():
        pdf_buffer = generate_vapt_pdf(sample_assessment)
        data = pdf_buffer.getvalue()
        assert len(data) > 1000
        # Valid PDF magic header
        assert data.startswith(b'%PDF-')


def test_pdf_generation_with_findings(app, sample_assessment):
    """Verify PDF generates properly when findings are present."""
    with app.app_context():
        f = VulnerabilityFinding(
            assessment_id=sample_assessment,
            title="Reflected XSS in Search",
            affected_url="https://test.target.local/search?q=1",
            http_method="GET",
            parameter="q",
            description="Detailed test description for PDF generation.",
            evidence="<script>alert(1)</script>",
            severity="High",
            owasp_category="A05:2025 — Injection",
            risk_score=75.0,
            risk_priority="High Priority",
            remediation_status="Open"
        )
        db.session.add(f)
        db.session.commit()

        pdf_buffer = generate_vapt_pdf(sample_assessment)
        data = pdf_buffer.getvalue()
        assert len(data) > 1500
        assert data.startswith(b'%PDF-')
