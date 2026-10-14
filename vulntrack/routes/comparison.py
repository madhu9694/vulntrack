"""
VulnTrack Assessment Comparison Blueprint.

Provides side-by-side analysis of baseline assessments versus post-remediation
scans, tracking risk reduction percentages and new/persisting findings.
"""

from flask import Blueprint, render_template, request, flash
from flask_login import login_required
from models import Assessment
from services.comparison import compare_assessments

comparison_bp = Blueprint('comparison', __name__, url_prefix='/comparison')


@comparison_bp.route('/', methods=['GET'])
@login_required
def index():
    baseline_id = request.args.get('baseline_id', type=int)
    retest_id = request.args.get('retest_id', type=int)

    assessments = Assessment.query.order_by(Assessment.created_at.asc()).all()
    comparison_data = None

    if baseline_id and retest_id:
        if baseline_id == retest_id:
            flash("Please choose two different assessments for a meaningful comparison.", "warning")
        else:
            try:
                comparison_data = compare_assessments(baseline_id, retest_id)
            except Exception as e:
                flash(f"Error computing comparison: {str(e)}", "danger")

    return render_template(
        'comparison/index.html',
        assessments=assessments,
        baseline_id=baseline_id,
        retest_id=retest_id,
        comparison=comparison_data
    )
