"""
VulnTrack Remediation Tracker Blueprint.

Tracks vulnerability remediation lifecycle, retesting outcomes, accepted risks,
and progress indicators across assessments.
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required
from extensions import db
from models import VulnerabilityFinding, Assessment
from forms import RemediationUpdateForm
from services.audit_service import log_action

remediation_bp = Blueprint('remediation', __name__, url_prefix='/remediation')


@remediation_bp.route('/')
@login_required
def index():
    assessment_id = request.args.get('assessment_id', type=int)

    query = VulnerabilityFinding.query
    if assessment_id:
        query = query.filter_by(assessment_id=assessment_id)

    all_findings = query.order_by(VulnerabilityFinding.risk_score.desc()).all()

    # Groupings
    grouped = {
        'Open': [f for f in all_findings if f.remediation_status == 'Open'],
        'In Progress': [f for f in all_findings if f.remediation_status == 'In Progress'],
        'Retest Pending': [f for f in all_findings if f.remediation_status == 'Retest Pending'],
        'Fixed': [f for f in all_findings if f.remediation_status == 'Fixed'],
        'Accepted Risk': [f for f in all_findings if f.remediation_status == 'Accepted Risk'],
        'Reopened': [f for f in all_findings if f.remediation_status == 'Reopened']
    }

    # Progress Calculation
    total = len(all_findings)
    fixed_count = len(grouped['Fixed'])
    accepted_count = len(grouped['Accepted Risk'])
    progress_pct = round((fixed_count / total * 100), 1) if total > 0 else 0.0

    # Critical & High open count
    urgent_open = [f for f in all_findings if f.severity in ['Critical', 'High'] and f.remediation_status != 'Fixed']

    assessments = Assessment.query.order_by(Assessment.name.asc()).all()

    return render_template(
        'remediation/index.html',
        grouped=grouped,
        total=total,
        fixed_count=fixed_count,
        accepted_count=accepted_count,
        progress_pct=progress_pct,
        urgent_open=urgent_open,
        assessments=assessments,
        current_assessment_id=assessment_id
    )


@remediation_bp.route('/update/<int:finding_id>', methods=['GET', 'POST'])
@login_required
def update(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    form = RemediationUpdateForm(obj=finding)

    if form.validate_on_submit():
        new_status = form.remediation_status.data
        old_status = finding.remediation_status

        finding.remediation_status = new_status
        finding.retest_result = form.retest_result.data or None
        finding.retest_notes = form.retest_notes.data.strip() if form.retest_notes.data else None
        finding.accepted_risk_justification = form.accepted_risk_justification.data.strip() if form.accepted_risk_justification.data else None

        if form.retest_result.data:
            finding.retest_date = datetime.utcnow()

        if new_status == 'Fixed' and old_status != 'Fixed':
            finding.fixed_at = datetime.utcnow()
        elif new_status != 'Fixed':
            finding.fixed_at = None

        db.session.commit()

        log_action(
            'STATUS_CHANGE',
            f"Finding #{finding.id} status changed from '{old_status}' to '{new_status}' (Retest: {finding.retest_result or 'None'})",
            target_id=finding.id
        )

        flash(f"Remediation status for '{finding.title}' updated to {new_status}.", "success")
        return redirect(url_for('remediation.index', assessment_id=finding.assessment_id))

    return render_template('remediation/update.html', form=form, finding=finding)
