"""
VulnTrack WTForms Definitions.

Server-side validated forms with CSRF protection for assessments, findings,
remediation updates, and authentication.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import (
    StringField, PasswordField, BooleanField, TextAreaField, SelectField,
    FloatField, DateField, SubmitField
)
from wtforms.validators import DataRequired, Length, URL, Optional, NumberRange
from services.owasp_mapper import OWASP_2025_CATEGORIES


class LoginForm(FlaskForm):
    """User authentication form."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class AssessmentForm(FlaskForm):
    """Assessment creation and edit form."""
    name = StringField('Assessment Name', validators=[DataRequired(), Length(max=150)])
    target_url = StringField('Target URL', validators=[DataRequired(), Length(max=255)])
    scope_notes = TextAreaField('Scope & Boundaries Notes', validators=[Optional()])
    tester = StringField('Security Tester Name', validators=[DataRequired(), Length(max=100)])
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[Optional()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('Planned', 'Planned'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Archived', 'Archived')
    ], default='In Progress', validators=[DataRequired()])
    submit = SubmitField('Save Assessment')


class FindingForm(FlaskForm):
    """Manual finding entry or editing (including Burp Suite findings)."""
    title = StringField('Vulnerability Title', validators=[DataRequired(), Length(max=255)])
    affected_url = StringField('Affected Endpoint / URL', validators=[DataRequired(), Length(max=1024)])
    http_method = SelectField('HTTP Method', choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE'),
        ('PATCH', 'PATCH'),
        ('OPTIONS', 'OPTIONS'),
        ('HEAD', 'HEAD')
    ], default='GET')
    parameter = StringField('Vulnerable Parameter', validators=[Optional(), Length(max=255)])
    description = TextAreaField('Detailed Description', validators=[DataRequired()])
    evidence = TextAreaField('Proof of Concept / Evidence / Request-Response', validators=[Optional()])

    severity = SelectField('Severity', choices=[
        ('Critical', 'Critical (100)'),
        ('High', 'High (80)'),
        ('Medium', 'Medium (55)'),
        ('Low', 'Low (30)'),
        ('Informational', 'Informational (10)')
    ], default='Medium', validators=[DataRequired()])

    confidence = SelectField('Confidence', choices=[
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('False Positive', 'False Positive')
    ], default='Medium')

    cvss_score = FloatField('CVSS Base Score (Optional)', validators=[Optional(), NumberRange(min=0.0, max=10.0)])
    cwe_id = StringField('CWE Identifier (e.g. CWE-89)', validators=[Optional(), Length(max=32)])
    
    owasp_category = SelectField(
        'OWASP Top 10:2025 Category',
        choices=[(cat, cat) for cat in OWASP_2025_CATEGORIES],
        default="Unclassified / General Security Issue",
        validators=[DataRequired()]
    )

    # Risk Engine Components (0 to 100)
    exploitability_level = SelectField('Exploitability Rating', choices=[
        ('100.0', 'Trivial / Public Exploit (100)'),
        ('75.0', 'PoC Available / Moderate Skill (75)'),
        ('45.0', 'Complex / Special Preconditions (45)'),
        ('15.0', 'Theoretical / Very Difficult (15)')
    ], default='45.0')

    business_impact = SelectField('Business Impact Rating', choices=[
        ('100.0', 'Critical (Complete Compromise / Regulatory Breach) (100)'),
        ('75.0', 'High (Sensitive Data Leakage / Account Takeover) (75)'),
        ('50.0', 'Medium (Limited Non-Critical Disclosure) (50)'),
        ('25.0', 'Low (Minor Internal Information Leak) (25)'),
        ('10.0', 'Negligible (Informational) (10)')
    ], default='50.0')

    exposure_level = SelectField('Exposure Rating', choices=[
        ('100.0', 'Public Internet / Unauthenticated (100)'),
        ('70.0', 'Public Internet / Authenticated User (70)'),
        ('40.0', 'Internal Corporate Network / VPN (40)'),
        ('15.0', 'Restricted Admin Segment / Localhost (15)')
    ], default='70.0')

    remediation_recommendation = TextAreaField('Remediation Guidance', validators=[Optional()])

    source_tool = SelectField('Source Tool', choices=[
        ('Manual', 'Manual Validation'),
        ('Burp Suite', 'Burp Suite Community / Pro'),
        ('OWASP ZAP', 'OWASP ZAP')
    ], default='Manual')

    remediation_status = SelectField('Remediation Status', choices=[
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Fixed', 'Fixed'),
        ('Accepted Risk', 'Accepted Risk'),
        ('Retest Pending', 'Retest Pending'),
        ('Reopened', 'Reopened')
    ], default='Open')

    notes = TextAreaField('Tester Notes', validators=[Optional()])
    submit = SubmitField('Save Finding')


class RemediationUpdateForm(FlaskForm):
    """Form for updating remediation status and recording retests."""
    remediation_status = SelectField('Remediation Status', choices=[
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Fixed', 'Fixed'),
        ('Accepted Risk', 'Accepted Risk'),
        ('Retest Pending', 'Retest Pending'),
        ('Reopened', 'Reopened')
    ], validators=[DataRequired()])

    retest_result = SelectField('Retest Outcome', choices=[
        ('', 'No Retest Yet'),
        ('Passed / Remediated', 'Passed / Remediated'),
        ('Failed / Persists', 'Failed / Persists'),
        ('Partially Remediated', 'Partially Remediated')
    ], validators=[Optional()])

    retest_notes = TextAreaField('Retest Verification Notes', validators=[Optional()])
    accepted_risk_justification = TextAreaField('Accepted Risk Business Justification', validators=[Optional()])
    submit = SubmitField('Update Remediation Status')


class ZapImportForm(FlaskForm):
    """Form to upload OWASP ZAP scan reports."""
    report_file = FileField(
        'OWASP ZAP Report File (.json or .xml)',
        validators=[
            FileRequired(),
            FileAllowed(['json', 'xml'], 'Only JSON or XML files are allowed!')
        ]
    )
    skip_duplicates = BooleanField('Skip duplicate findings instead of grouping them', default=False)
    submit = SubmitField('Upload and Parse Report')
