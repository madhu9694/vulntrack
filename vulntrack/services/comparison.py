"""
VulnTrack Before-and-After Assessment Comparison Service.

Enables penetration testers and security leads to compare a baseline assessment
against a post-remediation assessment, computing risk reduction percentages,
resolved items, persisting issues, and newly introduced vulnerabilities.
"""

from typing import Dict, Any, List
from extensions import db
from models import Assessment, VulnerabilityFinding


def compare_assessments(baseline_id: int, retest_id: int) -> Dict[str, Any]:
    """
    Perform deep before-and-after comparison between baseline and retest assessments.
    
    Safe zero-division handling, fingerprint-based vulnerability matching,
    and clear distinction between verified-fixed vs unobserved findings.
    """
    baseline = db.session.get(Assessment, baseline_id)
    retest = db.session.get(Assessment, retest_id)

    if not baseline or not retest:
        raise ValueError("Both baseline and retest assessment records must exist.")

    baseline_findings: List[VulnerabilityFinding] = baseline.findings.all()
    retest_findings: List[VulnerabilityFinding] = retest.findings.all()

    # Map by fingerprint hash
    baseline_map: Dict[str, VulnerabilityFinding] = {}
    for f in baseline_findings:
        if f.fingerprint_hash:
            baseline_map[f.fingerprint_hash] = f

    retest_map: Dict[str, VulnerabilityFinding] = {}
    for f in retest_findings:
        if f.fingerprint_hash:
            retest_map[f.fingerprint_hash] = f

    # Counts
    base_total = len(baseline_findings)
    retest_total = len(retest_findings)

    base_crit_high = sum(1 for f in baseline_findings if f.severity in ['Critical', 'High'])
    retest_crit_high = sum(1 for f in retest_findings if f.severity in ['Critical', 'High'])

    base_risk = sum(f.risk_score for f in baseline_findings if f.remediation_status != 'Fixed')
    retest_risk = sum(f.risk_score for f in retest_findings if f.remediation_status != 'Fixed')

    # Calculate percentage reductions with zero-division safety
    if base_total > 0:
        findings_reduction_pct = round(((base_total - retest_total) / base_total) * 100, 2)
    else:
        findings_reduction_pct = 0.0

    if base_risk > 0:
        risk_reduction_pct = round(((base_risk - retest_risk) / base_risk) * 100, 2)
    else:
        risk_reduction_pct = 0.0

    # Categorized lists of matching items
    fixed_or_remediated = []
    persisting_open = []
    new_findings = []
    not_observed_in_retest = []

    # Check baseline items against retest
    for fp, b_finding in baseline_map.items():
        if fp in retest_map:
            r_finding = retest_map[fp]
            if r_finding.remediation_status == 'Fixed' or r_finding.retest_result == 'Passed / Remediated':
                fixed_or_remediated.append({
                    'title': b_finding.title,
                    'severity': b_finding.severity,
                    'url': b_finding.affected_url,
                    'baseline_status': b_finding.remediation_status,
                    'retest_status': r_finding.remediation_status,
                    'notes': r_finding.retest_notes or 'Resolved in retest'
                })
            else:
                persisting_open.append({
                    'title': b_finding.title,
                    'severity': r_finding.severity,
                    'url': b_finding.affected_url,
                    'baseline_score': b_finding.risk_score,
                    'retest_score': r_finding.risk_score,
                    'status': r_finding.remediation_status
                })
        else:
            # VIVA NOTE: Crucial distinction between 'Fixed' vs 'Not Observed'!
            # Just because an automated scanner missed an endpoint in a second scan does NOT prove it's fixed.
            # If the user verified it as 'Fixed', we record it as remediated; otherwise, we flag it as
            # 'Not Observed in Retest Scan' so the security analyst knows to perform manual verification.
            if b_finding.remediation_status == 'Fixed':
                fixed_or_remediated.append({
                    'title': b_finding.title,
                    'severity': b_finding.severity,
                    'url': b_finding.affected_url,
                    'baseline_status': 'Fixed',
                    'retest_status': 'Fixed',
                    'notes': 'Confirmed fixed in baseline'
                })
            else:
                not_observed_in_retest.append({
                    'title': b_finding.title,
                    'severity': b_finding.severity,
                    'url': b_finding.affected_url,
                    'status': 'Not Observed in Retest Scan'
                })

    # Check newly introduced findings in retest
    for fp, r_finding in retest_map.items():
        if fp not in baseline_map:
            new_findings.append({
                'title': r_finding.title,
                'severity': r_finding.severity,
                'risk_score': r_finding.risk_score,
                'url': r_finding.affected_url,
                'status': r_finding.remediation_status
            })

    def get_severity_dist(findings):
        dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for f in findings:
            if f.severity in dist:
                dist[f.severity] += 1
        return dist

    return {
        'baseline': {
            'id': baseline.id,
            'name': baseline.name,
            'target_url': baseline.target_url,
            'total_findings': base_total,
            'crit_high_count': base_crit_high,
            'aggregate_risk': round(base_risk, 2),
            'severity_distribution': get_severity_dist(baseline_findings)
        },
        'retest': {
            'id': retest.id,
            'name': retest.name,
            'target_url': retest.target_url,
            'total_findings': retest_total,
            'crit_high_count': retest_crit_high,
            'aggregate_risk': round(retest_risk, 2),
            'severity_distribution': get_severity_dist(retest_findings)
        },
        'metrics': {
            'findings_reduction_pct': findings_reduction_pct,
            'risk_reduction_pct': risk_reduction_pct,
            'fixed_count': len(fixed_or_remediated),
            'persisting_count': len(persisting_open),
            'new_count': len(new_findings),
            'not_observed_count': len(not_observed_in_retest)
        },
        'lists': {
            'fixed_or_remediated': fixed_or_remediated,
            'persisting_open': persisting_open,
            'new_findings': new_findings,
            'not_observed_in_retest': not_observed_in_retest
        }
    }
