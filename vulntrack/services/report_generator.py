"""
VulnTrack Professional VAPT Report Generator using ReportLab.

Produces comprehensive, downloadable PDF penetration testing reports with:
- Formal cover page and metadata
- Executive summary, scope, and methodology
- Severity and OWASP category distribution tables
- Detailed vulnerability findings, evidence, explainable risk calculations
- Remediation guidance and validation statuses
- Dynamic page numbering ("Page X of Y") and headers/footers
"""

import io
import html
from datetime import datetime
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

from extensions import db
from models import Assessment, VulnerabilityFinding


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically calculate total page count
    and render 'Page X of Y' on every page along with header/footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        # Don't draw headers/footers on the cover page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header
        self.drawString(54, 750, "VulnTrack — College Cybersecurity Lab Project | Academic VAPT Assessment")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)

        # Running Footer
        page_text = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(558, 40, page_text)
        self.drawString(54, 40, "ACADEMIC SECURITY PROJECT — STRICTLY FOR AUTHORIZED LAB EVALUATION")
        self.line(54, 50, 558, 50)

        self.restoreState()


def safe_text(val) -> str:
    """Escape text for ReportLab XML/HTML-like syntax."""
    if val is None:
        return "N/A"
    return html.escape(str(val))


def generate_vapt_pdf(assessment_id: int) -> io.BytesIO:
    """Generate professional VAPT PDF report in-memory."""
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found.")

    findings: List[VulnerabilityFinding] = assessment.findings.order_by(
        VulnerabilityFinding.risk_score.desc()
    ).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceAfter=10
    )
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#d97706'),
        spaceAfter=22
    )
    h1_style = ParagraphStyle(
        'Heading1Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )
    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=4
    )

    story = []

    # ==================== COVER PAGE ====================
    story.append(Spacer(1, 40))
    # Brand tag
    story.append(Paragraph("<b>CYBERSECURITY LAB PROJECT — VULNTRACK PLATFORM</b>", ParagraphStyle(
        'BrandTag', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#f97316'), spaceAfter=15
    )))
    story.append(Paragraph("VAPT Assessment &amp; Risk Prioritization Report", title_style))
    story.append(Paragraph(f"Target: {safe_text(assessment.name)}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor('#f97316'), spaceBefore=5, spaceAfter=22))

    cover_meta = [
        [Paragraph("<b>Target Endpoint / Host:</b>", body_style), Paragraph(safe_text(assessment.target_url), body_style)],
        [Paragraph("<b>Student Security Tester:</b>", body_style), Paragraph(safe_text(assessment.tester), body_style)],
        [Paragraph("<b>Assessment Status:</b>", body_style), Paragraph(safe_text(assessment.status), body_style)],
        [Paragraph("<b>Lab Assessment Window:</b>", body_style), Paragraph(f"{assessment.start_date or 'N/A'} to {assessment.end_date or 'N/A'}", body_style)],
        [Paragraph("<b>Report Generated:</b>", body_style), Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), body_style)],
        [Paragraph("<b>Project Report ID:</b>", body_style), Paragraph(f"VT-CLG-{assessment.id:04d}-{datetime.utcnow().strftime('%Y%m%d')}", body_style)],
    ]
    t_cover = Table(cover_meta, colWidths=[160, 340])
    t_cover.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_cover)

    story.append(Spacer(1, 30))
    disclaimer_box = [
        [Paragraph(
            "<b>ACADEMIC ETHICAL USE &amp; AUTHORIZATION NOTICE</b><br/>"
            "This vulnerability report was prepared as part of a 2nd year Computer Science &amp; Engineering "
            "cybersecurity lab assessment. All testing was performed strictly against authorized academic targets "
            "under faculty supervision. Offensive exploitation outside lab parameters is strictly prohibited.",
            ParagraphStyle('DiscText', parent=body_style, fontSize=8.5, leading=12, textColor=colors.HexColor('#475569'))
        )]
    ]
    t_disc = Table(disclaimer_box, colWidths=[500])
    t_disc.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef3c7')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#f59e0b')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(t_disc)

    story.append(PageBreak())

    # ==================== EXECUTIVE SUMMARY ====================
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(Paragraph(
        f"An authorized Vulnerability Assessment and Penetration Testing (VAPT) evaluation was performed on "
        f"<b>{safe_text(assessment.name)}</b> ({safe_text(assessment.target_url)}). The objective was to identify security "
        f"weaknesses, evaluate the business impact of potential exploits, and provide prioritized remediation recommendations.",
        body_style
    ))
    if assessment.scope_notes:
        story.append(Paragraph(f"<b>Scope &amp; Constraints:</b> {safe_text(assessment.scope_notes)}", body_style))

    # Metric counts
    total = len(findings)
    crit = sum(1 for f in findings if f.severity == 'Critical')
    high = sum(1 for f in findings if f.severity == 'High')
    med = sum(1 for f in findings if f.severity == 'Medium')
    low = sum(1 for f in findings if f.severity == 'Low')
    info = sum(1 for f in findings if f.severity == 'Informational')
    fixed = sum(1 for f in findings if f.remediation_status == 'Fixed')
    open_cnt = total - fixed

    story.append(Spacer(1, 8))
    summary_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Count</b>", body_style), Paragraph("<b>Status Notes</b>", body_style)],
        [Paragraph("Total Findings", body_style), str(total), "Identified vulnerabilities across all scan phases"],
        [Paragraph("Open / Actionable Findings", body_style), str(open_cnt), "Currently awaiting remediation or retesting"],
        [Paragraph("Resolved / Fixed Findings", body_style), str(fixed), "Verified remediated by engineering team"],
        [Paragraph("Critical Severity Findings", body_style), str(crit), "Immediate attention required; potential full compromise"],
        [Paragraph("High Severity Findings", body_style), str(high), "Severe security weaknesses; elevated exploitability"],
        [Paragraph("Medium Severity Findings", body_style), str(med), "Moderate business or integrity impact"],
        [Paragraph("Low Severity Findings", body_style), str(low), "Low risk exposure; defense-in-depth improvements"],
        [Paragraph("Informational Findings", body_style), str(info), "Security disclosures and best practice notices"]
    ]
    t_summary = Table(summary_data, colWidths=[160, 60, 280])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_summary)

    # ==================== METHODOLOGY & RISK FORMULA ====================
    story.append(Spacer(1, 12))
    story.append(Paragraph("2. Assessment Methodology &amp; Risk Scoring", h1_style))
    story.append(Paragraph(
        "Testing followed the standard <b>OWASP Web Security Testing Guide (WSTG)</b> framework combining automated "
        "scanning via OWASP ZAP and manual verification via Burp Suite. Vulnerabilities are mapped to the <b>OWASP Top 10:2025</b> "
        "taxonomy.",
        body_style
    ))
    story.append(Paragraph(
        "<b>VulnTrack Deterministic Risk Scoring Formula:</b><br/>"
        "To provide transparent risk prioritization for stakeholders, overall risk scores (0–100) are computed as:<br/>"
        "<code>Risk Score = (Severity &times; 0.40) + (Exploitability &times; 0.25) + (Business Impact &times; 0.25) + (Exposure &times; 0.10)</code>",
        body_style
    ))

    # ==================== DETAILED FINDINGS ====================
    story.append(Spacer(1, 14))
    story.append(Paragraph("3. Detailed Vulnerability Findings", h1_style))

    if not findings:
        story.append(Paragraph("No vulnerability findings recorded for this assessment.", body_style))
    else:
        sev_colors = {
            'Critical': colors.HexColor('#ef4444'),
            'High': colors.HexColor('#f97316'),
            'Medium': colors.HexColor('#eab308'),
            'Low': colors.HexColor('#3b82f6'),
            'Informational': colors.HexColor('#64748b')
        }

        for idx, f in enumerate(findings, 1):
            sev_col = sev_colors.get(f.severity, colors.HexColor('#64748b'))
            
            finding_blocks = []
            finding_blocks.append(Spacer(1, 6))
            
            # Finding header bar
            header_table = Table(
                [[
                    Paragraph(f"<b>#{idx}. {safe_text(f.title)}</b>", ParagraphStyle('FHead', fontName='Helvetica-Bold', fontSize=10, textColor=colors.white)),
                    Paragraph(f"<b>{safe_text(f.severity)} | Risk Score: {f.risk_score}</b>", ParagraphStyle('FSev', fontName='Helvetica-Bold', fontSize=9, textColor=colors.white, alignment=2))
                ]],
                colWidths=[360, 140]
            )
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_col),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            finding_blocks.append(header_table)

            f_details = [
                [Paragraph("<b>Affected URL:</b>", body_style), Paragraph(f"<code>{safe_text(f.affected_url)}</code>", body_style)],
                [Paragraph("<b>Method &amp; Parameter:</b>", body_style), Paragraph(f"{safe_text(f.http_method)} {f'| Param: {safe_text(f.parameter)}' if f.parameter else ''}", body_style)],
                [Paragraph("<b>OWASP Top 10:</b>", body_style), Paragraph(safe_text(f.owasp_category), body_style)],
                [Paragraph("<b>CWE / Confidence:</b>", body_style), Paragraph(f"{safe_text(f.cwe_id or 'None')} | Confidence: {safe_text(f.confidence)}", body_style)],
                [Paragraph("<b>Risk Breakdown:</b>", body_style), Paragraph(f"Sev: {f.severity} (40%), Exploit: {f.exploitability_level} (25%), Impact: {f.business_impact} (25%), Exposure: {f.exposure_level} (10%)", body_style)],
                [Paragraph("<b>Remediation Status:</b>", body_style), Paragraph(f"<b>{safe_text(f.remediation_status)}</b> {f'| Retest: {safe_text(f.retest_result)}' if f.retest_result else ''}", body_style)],
                [Paragraph("<b>Description:</b>", body_style), Paragraph(safe_text(f.description), body_style)],
            ]

            if f.evidence:
                f_details.append([
                    Paragraph("<b>Evidence / PoC:</b>", body_style),
                    Paragraph(safe_text(f.evidence[:600] + ('...' if len(f.evidence) > 600 else '')), code_style)
                ])

            if f.remediation_recommendation:
                f_details.append([
                    Paragraph("<b>Recommendation:</b>", body_style),
                    Paragraph(safe_text(f.remediation_recommendation), body_style)
                ])

            if f.accepted_risk_justification:
                f_details.append([
                    Paragraph("<b>Accepted Risk Reason:</b>", body_style),
                    Paragraph(safe_text(f.accepted_risk_justification), body_style)
                ])

            t_f = Table(f_details, colWidths=[120, 380])
            t_f.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            finding_blocks.append(t_f)
            finding_blocks.append(Spacer(1, 10))

            story.append(KeepTogether(finding_blocks))

    # ==================== CONCLUSION & LIMITATIONS ====================
    story.append(Spacer(1, 14))
    story.append(Paragraph("4. Scope Limitations &amp; Conclusion", h1_style))
    story.append(Paragraph(
        "Security assessments represent a point-in-time evaluation based on available endpoints and authorization scope. "
        "The absence of findings does not guarantee complete security against emerging attack vectors. Regular retesting, "
        "automated CI/CD vulnerability scanning, and secure code review practices are strongly advised.",
        body_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer
