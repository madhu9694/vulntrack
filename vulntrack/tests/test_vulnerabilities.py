"""
Unit tests for Vulnerability Findings, Remediation Updates, and Audit Logging.
"""

from models import VulnerabilityFinding, AuditLog
from extensions import db


def test_vulnerability_lifecycle(auth_client, app, sample_assessment):
    """Test manual finding entry, detail viewing, status updates, and audit trails."""
    # 1. Create finding manually
    res = auth_client.post('/vulnerabilities/create', data={
        'assessment_id': sample_assessment,
        'title': 'Server-Side Template Injection',
        'affected_url': 'https://test.target.local/profile/template',
        'http_method': 'POST',
        'parameter': 'theme',
        'description': 'Jinja2 SSTI allows arbitrary code execution on backend worker.',
        'evidence': '{{7*7}} returns 49',
        'severity': 'Critical',
        'confidence': 'High',
        'cwe_id': 'CWE-94',
        'owasp_category': 'A05:2025 — Injection',
        'exploitability_level': '100.0',
        'business_impact': '100.0',
        'exposure_level': '100.0',
        'source_tool': 'Burp Suite',
        'remediation_status': 'Open'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Server-Side Template Injection' in res.data

    with app.app_context():
        finding = VulnerabilityFinding.query.filter_by(title='Server-Side Template Injection').first()
        assert finding is not None
        f_id = finding.id
        # Risk Score: (100*0.4) + (100*0.25) + (100*0.25) + (100*0.1) = 100.0
        assert finding.risk_score == 100.0
        assert finding.risk_priority == 'Critical Priority'

    # 2. View Finding Detail
    res_detail = auth_client.get(f'/vulnerabilities/{f_id}')
    assert res_detail.status_code == 200
    assert b'Risk Score Breakdown' in res_detail.data

    # 3. Update Remediation Status
    res_update = auth_client.post(f'/remediation/update/{f_id}', data={
        'remediation_status': 'Fixed',
        'retest_result': 'Passed / Remediated',
        'retest_notes': 'SSTI payload rendered as plain text.'
    }, follow_redirects=True)
    assert res_update.status_code == 200

    with app.app_context():
        updated_f = VulnerabilityFinding.query.get(f_id)
        assert updated_f.remediation_status == 'Fixed'
        assert updated_f.fixed_at is not None
        assert updated_f.retest_result == 'Passed / Remediated'

        # Verify audit logs captured the actions
        audit_records = AuditLog.query.filter_by(target_id=str(f_id)).all()
        assert len(audit_records) >= 1
        assert any(a.action_type in ['FINDING_CREATE', 'STATUS_CHANGE'] for a in audit_records)
