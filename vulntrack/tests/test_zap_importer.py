"""
Unit tests for OWASP ZAP Report Importer Service.
"""

import pytest
from pathlib import Path
from services.zap_importer import (
    parse_zap_json,
    parse_zap_xml,
    import_zap_report,
    map_zap_risk
)
from models import VulnerabilityFinding


def test_map_zap_risk():
    """Verify ZAP risk codes and labels translate correctly."""
    assert map_zap_risk('3') == 'High'
    assert map_zap_risk('High') == 'High'
    assert map_zap_risk('2') == 'Medium'
    assert map_zap_risk('1') == 'Low'
    assert map_zap_risk('0') == 'Informational'


def test_parse_sample_zap_json():
    """Verify reading synthetic sample ZAP JSON report."""
    sample_path = Path(__file__).resolve().parent.parent / 'sample_reports' / 'sample_zap_report.json'
    assert sample_path.exists(), "Sample JSON report must exist"

    content = sample_path.read_text(encoding='utf-8')
    alerts = parse_zap_json(content)
    assert len(alerts) >= 5
    assert any("SQL Injection" in a['title'] for a in alerts)
    assert any("Cross-Site Scripting" in a['title'] for a in alerts)


def test_parse_sample_zap_xml():
    """Verify reading synthetic sample ZAP XML report."""
    sample_path = Path(__file__).resolve().parent.parent / 'sample_reports' / 'sample_zap_report.xml'
    assert sample_path.exists(), "Sample XML report must exist"

    content = sample_path.read_text(encoding='utf-8')
    alerts = parse_zap_xml(content)
    assert len(alerts) >= 2
    assert any("SQL Injection" in a['title'] for a in alerts)


def test_malformed_input_handling():
    """Ensure malformed JSON or XML raises ValueError without crashing."""
    with pytest.raises(ValueError):
        parse_zap_json("{invalid json")

    with pytest.raises(ValueError):
        parse_zap_xml("<invalid xml")


def test_import_zap_report_into_db(app, sample_assessment):
    """Test importing report directly into SQLite assessment."""
    sample_path = Path(__file__).resolve().parent.parent / 'sample_reports' / 'sample_zap_report.json'
    content = sample_path.read_text(encoding='utf-8')

    with app.app_context():
        summary = import_zap_report(
            assessment_id=sample_assessment,
            file_content=content,
            file_type='json',
            skip_duplicates=False
        )
        assert summary['imported_count'] >= 5
        assert summary['invalid_count'] == 0

        # Now import same content again to test duplicate detection
        dup_summary = import_zap_report(
            assessment_id=sample_assessment,
            file_content=content,
            file_type='json',
            skip_duplicates=True
        )
        assert dup_summary['duplicates_skipped'] >= 5
