"""
VulnTrack Transparent Risk Scoring Engine.

Deterministic, explainable risk prioritization formula:
Risk Score = (Severity * 0.40) + (Exploitability * 0.25) + (Business Impact * 0.25) + (Exposure * 0.10)

Categorization:
- Critical Priority: 80.00 - 100.00
- High Priority: 60.00 - 79.99
- Medium Priority: 40.00 - 59.99
- Low Priority: 0.00 - 39.99
"""

from typing import Dict, Any, Tuple

# Predefined numerical mappings for standard severity labels
SEVERITY_WEIGHTS = {
    'Critical': 100.0,
    'High': 80.0,
    'Medium': 55.0,
    'Low': 30.0,
    'Informational': 10.0
}

# Exploitability scale with educational context for cybersecurity students
EXPLOITABILITY_PRESETS = {
    'Trivial / Public Exploit': 100.0,
    'Functional Exploit / PoC Available': 75.0,
    'Moderate / Specific Preconditions': 45.0,
    'Theoretical / Difficult': 15.0
}

# Business Impact scale
BUSINESS_IMPACT_PRESETS = {
    'Critical (Complete Compromise / Major Breach)': 100.0,
    'High (Confidential Data / Account Takeover)': 75.0,
    'Medium (Limited Data Disclosure / Disruption)': 50.0,
    'Low (Minor Information Leak)': 25.0,
    'Negligible (Cosmetic / No Direct Loss)': 10.0
}

# Exposure scale
EXPOSURE_PRESETS = {
    'Public Internet / Unauthenticated': 100.0,
    'Public Internet / Authenticated User': 70.0,
    'Internal Corporate Network / VPN': 40.0,
    'Restricted Admin / Isolated Segment': 15.0
}

# Default baseline fallback for automated imports where environmental context is unverified
DEFAULT_EXPLOITABILITY = 50.0
DEFAULT_BUSINESS_IMPACT = 50.0
DEFAULT_EXPOSURE = 70.0


def normalize_component_score(value: Any, default: float = 50.0) -> float:
    """Safely clamp and normalize any numeric component score between 0.0 and 100.0."""
    try:
        val = float(value)
        return max(0.0, min(100.0, val))
    except (ValueError, TypeError):
        return default


def get_severity_score(severity: str) -> float:
    """Return normalized severity score (0-100)."""
    return SEVERITY_WEIGHTS.get(str(severity).capitalize(), 30.0)


def calculate_risk_score(
    severity: str,
    exploitability: float = DEFAULT_EXPLOITABILITY,
    business_impact: float = DEFAULT_BUSINESS_IMPACT,
    exposure: float = DEFAULT_EXPOSURE
) -> Dict[str, Any]:
    """
    Calculate deterministic risk score and return breakdown dictionary.
    
    Formula:
        Risk = (Sev * 0.40) + (Exploit * 0.25) + (Impact * 0.25) + (Exposure * 0.10)
        
    NOTE FOR VIVA:
    In our 2nd year cybersecurity lab, we learned that raw CVSS alone doesn't reflect
    real-world context (e.g. an internal test server vs a public login page).
    Our project formula weights intrinsic severity (40%), ease of exploitation (25%),
    business impact (25%), and network exposure (10%) to guide realistic triage.
    """
    # Step 1: Map severity label to numerical base score (0 to 100)
    sev_score = get_severity_score(severity)
    
    # Step 2: Ensure all component values stay safely clamped between 0 and 100
    exp_score = normalize_component_score(exploitability, DEFAULT_EXPLOITABILITY)
    imp_score = normalize_component_score(business_impact, DEFAULT_BUSINESS_IMPACT)
    expo_score = normalize_component_score(exposure, DEFAULT_EXPOSURE)

    # Step 3: Calculate weighted contributions
    sev_contrib = sev_score * 0.40
    exp_contrib = exp_score * 0.25
    imp_contrib = imp_score * 0.25
    expo_contrib = expo_score * 0.10

    # Step 4: Sum and clamp total score to 0.00 - 100.00
    raw_score = sev_contrib + exp_contrib + imp_contrib + expo_contrib
    final_score = round(max(0.0, min(100.0, raw_score)), 2)

    # Step 5: Assign priority category for dashboard filtering
    priority, priority_class = get_risk_priority(final_score)

    return {
        'final_score': final_score,
        'priority': priority,
        'priority_class': priority_class,
        'breakdown': {
            'severity': {
                'raw': sev_score,
                'weight': 0.40,
                'contribution': round(sev_contrib, 2)
            },
            'exploitability': {
                'raw': exp_score,
                'weight': 0.25,
                'contribution': round(exp_contrib, 2)
            },
            'business_impact': {
                'raw': imp_score,
                'weight': 0.25,
                'contribution': round(imp_contrib, 2)
            },
            'exposure': {
                'raw': expo_score,
                'weight': 0.10,
                'contribution': round(expo_contrib, 2)
            }
        },
        'formula': f"({sev_score} * 0.40) + ({exp_score} * 0.25) + ({imp_score} * 0.25) + ({expo_score} * 0.10) = {final_score}"
    }


def get_risk_priority(score: float) -> Tuple[str, str]:
    """
    Return Priority label and CSS badge class based on strict thresholds:
    - Critical Priority: 80.00 - 100.00
    - High Priority: 60.00 - 79.99
    - Medium Priority: 40.00 - 59.99
    - Low Priority: 0.00 - 39.99
    """
    if score >= 80.0:
        return 'Critical Priority', 'danger'
    elif score >= 60.0:
        return 'High Priority', 'warning'
    elif score >= 40.0:
        return 'Medium Priority', 'info'
    else:
        return 'Low Priority', 'secondary'
