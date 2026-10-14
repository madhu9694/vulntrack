"""
VulnTrack Assessments Blueprint.

Manages security testing engagements, target scopes, and timelines.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from extensions import db
from models import Assessment, VulnerabilityFinding
from forms import AssessmentForm
from services.audit_service import log_action

assessments_bp = Blueprint('assessments', __name__, url_prefix='/assessments')


@assessments_bp.route('/')
@login_required
def index():
    status_filter = request.args.get('status')
    search_query = request.args.get('q', '').strip()

    query = Assessment.query

    if status_filter:
        query = query.filter_by(status=status_filter)
    if search_query:
        query = query.filter(
            (Assessment.name.ilike(f'%{search_query}%')) |
            (Assessment.target_url.ilike(f'%{search_query}%')) |
            (Assessment.tester.ilike(f'%{search_query}%'))
        )

    assessments = query.order_by(Assessment.created_at.desc()).all()
    return render_template(
        'assessments/index.html',
        assessments=assessments,
        current_status=status_filter,
        search_query=search_query
    )


@assessments_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = AssessmentForm()
    if form.validate_on_submit():
        assessment = Assessment(
            name=form.name.data.strip(),
            target_url=form.target_url.data.strip(),
            scope_notes=form.scope_notes.data.strip() if form.scope_notes.data else None,
            tester=form.tester.data.strip(),
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            status=form.status.data
        )
        db.session.add(assessment)
        db.session.commit()

        log_action(
            'ASSESSMENT_CREATE',
            f"Created assessment '{assessment.name}' (Target: {assessment.target_url})",
            target_id=assessment.id
        )
        flash(f"Assessment '{assessment.name}' successfully created.", "success")
        return redirect(url_for('assessments.detail', assessment_id=assessment.id))

    return render_template('assessments/create.html', form=form)


@assessments_bp.route('/<int:assessment_id>')
@login_required
def detail(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    findings = assessment.findings.order_by(VulnerabilityFinding.risk_score.desc()).all()
    return render_template('assessments/detail.html', assessment=assessment, findings=findings)


@assessments_bp.route('/<int:assessment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    form = AssessmentForm(obj=assessment)

    if form.validate_on_submit():
        assessment.name = form.name.data.strip()
        assessment.target_url = form.target_url.data.strip()
        assessment.scope_notes = form.scope_notes.data.strip() if form.scope_notes.data else None
        assessment.tester = form.tester.data.strip()
        assessment.start_date = form.start_date.data
        assessment.end_date = form.end_date.data
        assessment.status = form.status.data

        db.session.commit()
        log_action(
            'ASSESSMENT_UPDATE',
            f"Updated assessment '{assessment.name}'",
            target_id=assessment.id
        )
        flash("Assessment updated successfully.", "success")
        return redirect(url_for('assessments.detail', assessment_id=assessment.id))

    return render_template('assessments/edit.html', form=form, assessment=assessment)


@assessments_bp.route('/<int:assessment_id>/delete', methods=['POST'])
@login_required
def delete(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    name = assessment.name
    db.session.delete(assessment)
    db.session.commit()

    log_action('ASSESSMENT_DELETE', f"Deleted assessment '{name}' and associated findings", target_id=assessment_id)
    flash(f"Assessment '{name}' deleted.", "info")
    return redirect(url_for('assessments.index'))
