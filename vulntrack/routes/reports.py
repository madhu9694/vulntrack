"""
VulnTrack Reports Blueprint.

Handles generation and download of professional VAPT penetration test reports
using ReportLab.
"""

from datetime import datetime
from flask import Blueprint, render_template, send_file, flash, redirect, url_for
from flask_login import login_required
from models import Assessment
from services.report_generator import generate_vapt_pdf
from services.audit_service import log_action

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')


@reports_bp.route('/')
@login_required
def index():
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).all()
    return render_template('reports/index.html', assessments=assessments)


@reports_bp.route('/download/<int:assessment_id>')
@login_required
def download_pdf(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)

    try:
        pdf_buffer = generate_vapt_pdf(assessment_id)
        
        filename = f"VulnTrack_VAPT_Report_{assessment.id}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        log_action(
            'REPORT_GENERATION',
            f"Generated VAPT PDF Report for Assessment '{assessment.name}'",
            target_id=assessment.id
        )

        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash(f"Error generating PDF report: {str(e)}", "danger")
        return redirect(url_for('reports.index'))
