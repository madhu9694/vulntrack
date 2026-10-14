"""
Unit tests for VulnTrack Risk Scoring Engine.
"""

import pytest
from services.risk_engine import (
    calculate_risk_score,
    get_risk_priority,
    get_severity_score,
    normalize_component_score
)


def test_severity_weights():
    """Verify standard severity weights."""
    assert get_severity_score('Critical') == 100.0
    assert get_severity_score('High') == 80.0
    assert get_severity_score('Medium') == 55.0
    assert get_severity_score('Low') == 30.0
    assert get_severity_score('Informational') == 10.0
    # Case insensitivity & fallback
    assert get_severity_score('critical') == 100.0
    assert get_severity_score('Unknown') == 30.0


def test_risk_formula_calculation():
    """
    Test deterministic calculation:
    Risk Score = (Sev * 0.40) + (Exploit * 0.25) + (Impact * 0.25) + (Exposure * 0.10)
    """
    # Critical (100 * 0.4 = 40) + Exploit (75 * 0.25 = 18.75) + Impact (75 * 0.25 = 18.75) + Exposure (100 * 0.1 = 10)
    # Expected: 40 + 18.75 + 18.75 + 10 = 87.5
    res = calculate_risk_score(
        severity='Critical',
        exploitability=75.0,
        business_impact=75.0,
        exposure=100.0
    )
    assert res['final_score'] == 87.5
    assert res['priority'] == 'Critical Priority'
    assert res['breakdown']['severity']['contribution'] == 40.0
    assert res['breakdown']['exploitability']['contribution'] == 18.75
    assert res['breakdown']['business_impact']['contribution'] == 18.75
    assert res['breakdown']['exposure']['contribution'] == 10.0


def test_priority_boundaries():
    """
    Test strict boundaries:
    - Critical Priority: 80.00 - 100.00
    - High Priority: 60.00 - 79.99
    - Medium Priority: 40.00 - 59.99
    - Low Priority: 0.00 - 39.99
    """
    # 100.0 -> Critical
    label, cls = get_risk_priority(100.0)
    assert label == 'Critical Priority'
    assert cls == 'danger'

    # Exactly 80.0 -> Critical
    label, cls = get_risk_priority(80.0)
    assert label == 'Critical Priority'

    # 79.99 -> High
    label, cls = get_risk_priority(79.99)
    assert label == 'High Priority'
    assert cls == 'warning'

    # Exactly 60.0 -> High
    label, cls = get_risk_priority(60.0)
    assert label == 'High Priority'

    # 59.99 -> Medium
    label, cls = get_risk_priority(59.99)
    assert label == 'Medium Priority'
    assert cls == 'info'

    # Exactly 40.0 -> Medium
    label, cls = get_risk_priority(40.0)
    assert label == 'Medium Priority'

    # 39.99 -> Low
    label, cls = get_risk_priority(39.99)
    assert label == 'Low Priority'
    assert cls == 'secondary'

    # 0.0 -> Low
    label, cls = get_risk_priority(0.0)
    assert label == 'Low Priority'


def test_clamping_and_normalization():
    """Verify values above 100 or below 0 are clamped safely."""
    assert normalize_component_score(150.0) == 100.0
    assert normalize_component_score(-50.0) == 0.0
    assert normalize_component_score('invalid', default=50.0) == 50.0
