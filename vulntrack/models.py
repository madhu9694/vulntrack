from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from extensions import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    """Local user account for authentication and authorization."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='Tester')  # Admin, Tester, Viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'Admin'

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Assessment(db.Model):
    """Security assessment engagement metadata."""
    __tablename__ = 'assessments'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    target_url = db.Column(db.String(255), nullable=False)
    scope_notes = db.Column(db.Text, nullable=True)
    tester = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Planned')  # Planned, In Progress, Completed, Archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Relationship to findings
    findings = db.relationship(
        'VulnerabilityFinding',
        backref='assessment',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    @property
    def total_findings(self):
        return self.findings.count()

    @property
    def open_findings(self):
        return self.findings.filter(
            VulnerabilityFinding.remediation_status.in_(['Open', 'In Progress', 'Retest Pending', 'Reopened'])
        ).count()

    @property
    def critical_high_count(self):
        return self.findings.filter(
            VulnerabilityFinding.severity.in_(['Critical', 'High']),
            VulnerabilityFinding.remediation_status != 'Fixed'
        ).count()

    @property
    def fixed_count(self):
        return self.findings.filter_by(remediation_status='Fixed').count()

    @property
    def aggregate_risk_score(self):
        """Sum of risk scores for all open findings."""
        open_items = self.findings.filter(
            VulnerabilityFinding.remediation_status.in_(['Open', 'In Progress', 'Retest Pending', 'Reopened'])
        ).all()
        return round(sum(f.risk_score for f in open_items), 2)

    def __repr__(self):
        return f'<Assessment {self.id}: {self.name} [{self.status}]>'


class VulnerabilityFinding(db.Model):
    """Vulnerability finding identified through automated or manual testing."""
    __tablename__ = 'vulnerability_findings'

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(
        db.Integer,
        db.ForeignKey('assessments.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    # Core identification
    title = db.Column(db.String(255), nullable=False, index=True)
    affected_url = db.Column(db.String(1024), nullable=False)
    http_method = db.Column(db.String(16), default='GET', nullable=False)
    parameter = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=True)

    # Classifications
    severity = db.Column(db.String(32), nullable=False, index=True)  # Critical, High, Medium, Low, Informational
    confidence = db.Column(db.String(32), default='Medium', nullable=False)  # High, Medium, Low, False Positive
    cvss_score = db.Column(db.Float, nullable=True)
    owasp_category = db.Column(db.String(128), nullable=False, index=True)
    owasp_year = db.Column(db.String(16), default='2025', nullable=False)
    cwe_id = db.Column(db.String(32), nullable=True, index=True)

    # Risk metrics (Explainable 40/25/25/10 system)
    exploitability_level = db.Column(db.Float, default=50.0, nullable=False)
    business_impact = db.Column(db.Float, default=50.0, nullable=False)
    exposure_level = db.Column(db.Float, default=70.0, nullable=False)
    risk_score = db.Column(db.Float, default=0.0, nullable=False, index=True)
    risk_priority = db.Column(db.String(32), default='Low Priority', nullable=False)  # Critical, High, Medium, Low Priority

    # Remediation tracking
    remediation_recommendation = db.Column(db.Text, nullable=True)
    remediation_status = db.Column(db.String(32), default='Open', nullable=False, index=True)
    # Statuses: Open, In Progress, Fixed, Accepted Risk, Retest Pending, Reopened
    accepted_risk_justification = db.Column(db.Text, nullable=True)
    fixed_at = db.Column(db.DateTime, nullable=True)

    # Retest outcomes
    retest_result = db.Column(db.String(64), nullable=True)  # Passed / Remediated, Failed / Persists, Partially Remediated
    retest_notes = db.Column(db.Text, nullable=True)
    retest_date = db.Column(db.DateTime, nullable=True)

    # Meta and tool details
    notes = db.Column(db.Text, nullable=True)
    source_tool = db.Column(db.String(64), default='Manual', nullable=False)  # Manual, OWASP ZAP, Burp Suite
    first_discovered_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_observed_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Deduplication
    fingerprint_hash = db.Column(db.String(64), nullable=True, index=True)
    duplicate_group_id = db.Column(db.String(64), nullable=True, index=True)
    is_duplicate = db.Column(db.Boolean, default=False, nullable=False)
    original_finding_id = db.Column(
        db.Integer,
        db.ForeignKey('vulnerability_findings.id', ondelete='SET NULL'),
        nullable=True
    )

    # Self-referential relationship for duplicates
    duplicates = db.relationship(
        'VulnerabilityFinding',
        backref=db.backref('original_finding', remote_side=[id]),
        foreign_keys=[original_finding_id],
        lazy='dynamic'
    )

    def is_open(self):
        return self.remediation_status in ['Open', 'In Progress', 'Retest Pending', 'Reopened']

    def is_fixed(self):
        return self.remediation_status == 'Fixed'

    def is_accepted_risk(self):
        return self.remediation_status == 'Accepted Risk'

    def __repr__(self):
        return f'<VulnerabilityFinding {self.id}: {self.title} [{self.severity} / {self.risk_priority}]>'


class AuditLog(db.Model):
    """Audit log tracking system-wide security actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(64), nullable=True)
    action_type = db.Column(db.String(64), nullable=False, index=True)
    target_id = db.Column(db.String(64), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)

    def __repr__(self):
        return f'<AuditLog {self.id}: {self.action_type} by {self.username} at {self.timestamp}>'
