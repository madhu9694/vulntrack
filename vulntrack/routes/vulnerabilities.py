"""
VulnTrack Vulnerabilities Blueprint.

Handles findings repository, search, filtering, manual entry (Burp Suite),
OWASP ZAP report uploads, risk score recalculations, and duplicate resolution.
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required
from extensions import db
from models import VulnerabilityFinding, Assessment
from forms import FindingForm, ZapImportForm
from services.risk_engine import calculate_risk_score
from services.owasp_mapper import suggest_owasp_category, OWASP_2025_CATEGORIES
from services.deduplication import generate_finding_fingerprint, find_matching_original
from services.zap_importer import import_zap_report
from services.audit_service import log_action

vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/vulnerabilities')


@vulnerabilities_bp.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    search_q = request.args.get('q', '').strip()
    assessment_id = request.args.get('assessment_id', type=int)
    severity = request.args.get('severity')
    status = request.args.get('status')
    owasp_cat = request.args.get('owasp')
    sort_by = request.args.get('sort', 'risk_desc')

    query = VulnerabilityFinding.query

    if assessment_id:
        query = query.filter_by(assessment_id=assessment_id)
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(remediation_status=status)
    if owasp_cat:
        query = query.filter_by(owasp_category=owasp_cat)
    if search_q:
        query = query.filter(
            (VulnerabilityFinding.title.ilike(f'%{search_q}%')) |
            (VulnerabilityFinding.affected_url.ilike(f'%{search_q}%')) |
            (VulnerabilityFinding.description.ilike(f'%{search_q}%')) |
            (VulnerabilityFinding.cwe_id.ilike(f'%{search_q}%'))
        )

    # Sorting
    if sort_by == 'risk_asc':
        query = query.order_by(VulnerabilityFinding.risk_score.asc())
    elif sort_by == 'date_desc':
        query = query.order_by(VulnerabilityFinding.first_discovered_date.desc())
    elif sort_by == 'date_asc':
        query = query.order_by(VulnerabilityFinding.first_discovered_date.asc())
    elif sort_by == 'title_asc':
        query = query.order_by(VulnerabilityFinding.title.asc())
    else:  # 'risk_desc' default
        query = query.order_by(VulnerabilityFinding.risk_score.desc())

    findings_pagination = query.paginate(page=page, per_page=15, error_out=False)
    assessments = Assessment.query.order_by(Assessment.name.asc()).all()

    return render_template(
        'vulnerabilities/index.html',
        findings_pagination=findings_pagination,
        assessments=assessments,
        current_assessment_id=assessment_id,
        current_severity=severity,
        current_status=status,
        current_owasp=owasp_cat,
        search_query=search_q,
        sort_by=sort_by,
        owasp_categories=OWASP_2025_CATEGORIES
    )


@vulnerabilities_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    assessment_id = request.args.get('assessment_id', type=int)
    form = FindingForm()

    # Pre-select assessment if passed in URL
    assessments = Assessment.query.order_by(Assessment.name.asc()).all()
    if not assessments:
        flash("Please create an assessment first before adding vulnerability findings.", "warning")
        return redirect(url_for('assessments.create'))

    if form.validate_on_submit():
        target_assessment_id = request.form.get('assessment_id', type=int) or assessment_id
        if not target_assessment_id:
            flash("Please choose an assessment to associate this finding with.", "danger")
            return render_template('vulnerabilities/create.html', form=form, assessments=assessments, assessment_id=assessment_id)

        # Calculate explainable risk score
        risk_res = calculate_risk_score(
            severity=form.severity.data,
            exploitability=float(form.exploitability_level.data),
            business_impact=float(form.business_impact.data),
            exposure=float(form.exposure_level.data)
        )

        # Generate deduplication fingerprint
        fingerprint = generate_finding_fingerprint(
            title=form.title.data.strip(),
            affected_url=form.affected_url.data.strip(),
            http_method=form.http_method.data,
            parameter=form.parameter.data.strip() if form.parameter.data else None,
            cwe_id=form.cwe_id.data.strip() if form.cwe_id.data else None
        )

        original_match = find_matching_original(
            fingerprint=fingerprint,
            current_assessment_id=target_assessment_id
        )

        is_dup = bool(original_match)
        original_id = original_match.id if original_match else None

        finding = VulnerabilityFinding(
            assessment_id=target_assessment_id,
            title=form.title.data.strip(),
            affected_url=form.affected_url.data.strip(),
            http_method=form.http_method.data,
            parameter=form.parameter.data.strip() if form.parameter.data else None,
            description=form.description.data.strip(),
            evidence=form.evidence.data.strip() if form.evidence.data else None,
            severity=form.severity.data,
            confidence=form.confidence.data,
            cvss_score=form.cvss_score.data,
            cwe_id=form.cwe_id.data.strip() if form.cwe_id.data else None,
            owasp_category=form.owasp_category.data,
            owasp_year="2025",
            exploitability_level=float(form.exploitability_level.data),
            business_impact=float(form.business_impact.data),
            exposure_level=float(form.exposure_level.data),
            risk_score=risk_res['final_score'],
            risk_priority=risk_res['priority'],
            remediation_recommendation=form.remediation_recommendation.data.strip() if form.remediation_recommendation.data else None,
            source_tool=form.source_tool.data,
            remediation_status=form.remediation_status.data,
            notes=form.notes.data.strip() if form.notes.data else None,
            fingerprint_hash=fingerprint,
            duplicate_group_id=fingerprint[:12],
            is_duplicate=is_dup,
            original_finding_id=original_id
        )

        db.session.add(finding)
        db.session.commit()

        log_action(
            'FINDING_CREATE',
            f"Created finding '{finding.title}' with Risk Score {finding.risk_score} (Tool: {finding.source_tool})",
            target_id=finding.id
        )

        if is_dup:
            flash(f"Finding recorded. Note: Flagged as a likely duplicate of Finding #{original_id}.", "warning")
        else:
            flash(f"Finding '{finding.title}' successfully recorded.", "success")

        return redirect(url_for('vulnerabilities.detail', finding_id=finding.id))

    return render_template(
        'vulnerabilities/create.html',
        form=form,
        assessments=assessments,
        assessment_id=assessment_id
    )


@vulnerabilities_bp.route('/<int:finding_id>')
@login_required
def detail(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    # Recalculate trace for mathematical presentation in UI/viva
    risk_calc = calculate_risk_score(
        severity=finding.severity,
        exploitability=finding.exploitability_level,
        business_impact=finding.business_impact,
        exposure=finding.exposure_level
    )
    # Check related duplicates in the same fingerprint group
    related_duplicates = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.fingerprint_hash == finding.fingerprint_hash,
        VulnerabilityFinding.id != finding.id
    ).all()

    return render_template(
        'vulnerabilities/detail.html',
        finding=finding,
        risk_calc=risk_calc,
        related_duplicates=related_duplicates
    )


@vulnerabilities_bp.route('/<int:finding_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    form = FindingForm(obj=finding)

    # Convert numeric fields to string for SelectField values if needed
    if request.method == 'GET':
        form.exploitability_level.data = str(float(finding.exploitability_level))
        form.business_impact.data = str(float(finding.business_impact))
        form.exposure_level.data = str(float(finding.exposure_level))

    assessments = Assessment.query.order_by(Assessment.name.asc()).all()

    if form.validate_on_submit():
        target_assessment_id = request.form.get('assessment_id', type=int) or finding.assessment_id

        # Recalculate risk score
        risk_res = calculate_risk_score(
            severity=form.severity.data,
            exploitability=float(form.exploitability_level.data),
            business_impact=float(form.business_impact.data),
            exposure=float(form.exposure_level.data)
        )

        fingerprint = generate_finding_fingerprint(
            title=form.title.data.strip(),
            affected_url=form.affected_url.data.strip(),
            http_method=form.http_method.data,
            parameter=form.parameter.data.strip() if form.parameter.data else None,
            cwe_id=form.cwe_id.data.strip() if form.cwe_id.data else None
        )

        old_score = finding.risk_score
        finding.assessment_id = target_assessment_id
        finding.title = form.title.data.strip()
        finding.affected_url = form.affected_url.data.strip()
        finding.http_method = form.http_method.data
        finding.parameter = form.parameter.data.strip() if form.parameter.data else None
        finding.description = form.description.data.strip()
        finding.evidence = form.evidence.data.strip() if form.evidence.data else None
        finding.severity = form.severity.data
        finding.confidence = form.confidence.data
        finding.cvss_score = form.cvss_score.data
        finding.cwe_id = form.cwe_id.data.strip() if form.cwe_id.data else None
        finding.owasp_category = form.owasp_category.data
        finding.exploitability_level = float(form.exploitability_level.data)
        finding.business_impact = float(form.business_impact.data)
        finding.exposure_level = float(form.exposure_level.data)
        finding.risk_score = risk_res['final_score']
        finding.risk_priority = risk_res['priority']
        finding.remediation_recommendation = form.remediation_recommendation.data.strip() if form.remediation_recommendation.data else None
        finding.source_tool = form.source_tool.data
        finding.remediation_status = form.remediation_status.data
        finding.notes = form.notes.data.strip() if form.notes.data else None
        finding.fingerprint_hash = fingerprint
        finding.duplicate_group_id = fingerprint[:12]
        finding.last_observed_date = datetime.utcnow()

        db.session.commit()
        log_action(
            'FINDING_UPDATE',
            f"Updated finding #{finding.id} '{finding.title}'. Score changed from {old_score} to {finding.risk_score}",
            target_id=finding.id
        )
        flash("Finding updated successfully.", "success")
        return redirect(url_for('vulnerabilities.detail', finding_id=finding.id))

    return render_template(
        'vulnerabilities/edit.html',
        form=form,
        finding=finding,
        assessments=assessments
    )


@vulnerabilities_bp.route('/<int:finding_id>/delete', methods=['POST'])
@login_required
def delete(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    assessment_id = finding.assessment_id
    title = finding.title
    db.session.delete(finding)
    db.session.commit()

    log_action('FINDING_DELETE', f"Deleted finding '{title}'", target_id=finding_id)
    flash(f"Finding '{title}' was deleted.", "info")
    return redirect(url_for('assessments.detail', assessment_id=assessment_id))


@vulnerabilities_bp.route('/<int:finding_id>/resolve-duplicate', methods=['POST'])
@login_required
def resolve_duplicate(finding_id):
    """Toggle duplicate state for a finding (handles false positives)."""
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    finding.is_duplicate = not finding.is_duplicate
    if not finding.is_duplicate:
        finding.original_finding_id = None
    db.session.commit()

    state_desc = "marked as an independent finding" if not finding.is_duplicate else "flagged as duplicate"
    log_action('DUPLICATE_RESOLVE', f"Finding #{finding.id} {state_desc}.", target_id=finding.id)
    flash(f"Duplicate status updated: Finding is now {state_desc}.", "info")
    return redirect(url_for('vulnerabilities.detail', finding_id=finding.id))


@vulnerabilities_bp.route('/import/<int:assessment_id>', methods=['GET', 'POST'])
@login_required
def import_zap(assessment_id):
    """Import OWASP ZAP scan report (JSON or XML)."""
    assessment = Assessment.query.get_or_404(assessment_id)
    form = ZapImportForm()

    if form.validate_on_submit():
        file_obj = form.report_file.data
        filename = file_obj.filename.lower()
        file_content = file_obj.read().decode('utf-8', errors='replace')

        file_type = 'json' if filename.endswith('.json') else 'xml'

        try:
            summary = import_zap_report(
                assessment_id=assessment.id,
                file_content=file_content,
                file_type=file_type,
                skip_duplicates=form.skip_duplicates.data
            )

            log_action(
                'IMPORT_ZAP',
                f"Imported ZAP {file_type.upper()} into Assessment #{assessment.id}: {summary['imported_count']} new, {summary['duplicates_count']} duplicates.",
                target_id=assessment.id
            )

            flash(
                f"Report import completed! Total: {summary['total_parsed']} | Imported: {summary['imported_count']} | "
                f"Duplicates: {summary['duplicates_count']} | Skipped: {summary['duplicates_skipped']} | Invalid: {summary['invalid_count']}",
                "success"
            )
            return redirect(url_for('assessments.detail', assessment_id=assessment.id))

        except Exception as e:
            flash(f"Failed to process scan report: {str(e)}", "danger")

    return render_template('vulnerabilities/import.html', form=form, assessment=assessment)
