"""
VulnTrack Dashboard Blueprint.

Calculates aggregated security metrics, generates dataset payloads for Chart.js,
and presents top-risk findings and active assessment status.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from sqlalchemy import func
from extensions import db
from models import Assessment, VulnerabilityFinding

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    assessment_id = request.args.get('assessment_id', type=int)

    # Base query for findings
    query = VulnerabilityFinding.query
    if assessment_id:
        query = query.filter_by(assessment_id=assessment_id)

    # Core Metrics
    total_assessments = Assessment.query.count()
    total_findings = query.count()
    open_findings = query.filter(
        VulnerabilityFinding.remediation_status.in_(['Open', 'In Progress', 'Retest Pending', 'Reopened'])
    ).count()
    crit_high_findings = query.filter(
        VulnerabilityFinding.severity.in_(['Critical', 'High']),
        VulnerabilityFinding.remediation_status != 'Fixed'
    ).count()
    fixed_findings = query.filter_by(remediation_status='Fixed').count()
    retest_pending = query.filter_by(remediation_status='Retest Pending').count()

    # Severity distribution data
    sev_counts = {
        'Critical': query.filter_by(severity='Critical').count(),
        'High': query.filter_by(severity='High').count(),
        'Medium': query.filter_by(severity='Medium').count(),
        'Low': query.filter_by(severity='Low').count(),
        'Informational': query.filter_by(severity='Informational').count()
    }

    # Remediation Status distribution data
    status_counts = {
        'Open': query.filter_by(remediation_status='Open').count(),
        'In Progress': query.filter_by(remediation_status='In Progress').count(),
        'Fixed': query.filter_by(remediation_status='Fixed').count(),
        'Accepted Risk': query.filter_by(remediation_status='Accepted Risk').count(),
        'Retest Pending': query.filter_by(remediation_status='Retest Pending').count(),
        'Reopened': query.filter_by(remediation_status='Reopened').count()
    }

    # Risk Priority distribution
    risk_counts = {
        'Critical Priority (80-100)': query.filter(VulnerabilityFinding.risk_score >= 80.0).count(),
        'High Priority (60-79.9)': query.filter(VulnerabilityFinding.risk_score >= 60.0, VulnerabilityFinding.risk_score < 80.0).count(),
        'Medium Priority (40-59.9)': query.filter(VulnerabilityFinding.risk_score >= 40.0, VulnerabilityFinding.risk_score < 60.0).count(),
        'Low Priority (0-39.9)': query.filter(VulnerabilityFinding.risk_score < 40.0).count()
    }

    # OWASP Top 10 breakdown (top categories)
    owasp_stats = db.session.query(
        VulnerabilityFinding.owasp_category,
        func.count(VulnerabilityFinding.id)
    )
    if assessment_id:
        owasp_stats = owasp_stats.filter(VulnerabilityFinding.assessment_id == assessment_id)
    owasp_results = owasp_stats.group_by(VulnerabilityFinding.owasp_category).order_by(
        func.count(VulnerabilityFinding.id).desc()
    ).limit(8).all()

    owasp_labels = [r[0].split('—')[0].strip() if '—' in r[0] else r[0][:20] for r in owasp_results]
    owasp_counts = [r[1] for r in owasp_results]

    # Top High-Priority Open Findings
    top_findings = query.filter(
        VulnerabilityFinding.remediation_status != 'Fixed'
    ).order_by(VulnerabilityFinding.risk_score.desc()).limit(7).all()

    # Recent assessments
    recent_assessments = Assessment.query.order_by(Assessment.created_at.desc()).limit(5).all()
    all_assessments = Assessment.query.order_by(Assessment.name.asc()).all()

    # Selected assessment object if filtered
    selected_assessment = Assessment.query.get(assessment_id) if assessment_id else None

    return render_template(
        'dashboard/index.html',
        total_assessments=total_assessments,
        total_findings=total_findings,
        open_findings=open_findings,
        crit_high_findings=crit_high_findings,
        fixed_findings=fixed_findings,
        retest_pending=retest_pending,
        sev_counts=sev_counts,
        status_counts=status_counts,
        risk_counts=risk_counts,
        owasp_labels=owasp_labels,
        owasp_counts=owasp_counts,
        top_findings=top_findings,
        recent_assessments=recent_assessments,
        all_assessments=all_assessments,
        selected_assessment=selected_assessment,
        current_assessment_id=assessment_id
    )
