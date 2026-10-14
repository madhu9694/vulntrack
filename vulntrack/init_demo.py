"""
VulnTrack Demonstration Data Seeder.

Generates realistic, clearly labeled synthetic security assessments and findings
covering OWASP Top 10:2025 taxonomy, varying severity and priority levels,
duplicate clusters, and before-and-after retest scenarios for viva demonstrations.
"""

from datetime import datetime, date, timedelta
from extensions import db
from models import User, Assessment, VulnerabilityFinding, AuditLog
from services.risk_engine import calculate_risk_score
from services.deduplication import generate_finding_fingerprint
from app import create_app


def populate_demo_data():
    """Seed synthetic assessments and vulnerability findings."""
    db.drop_all()
    db.create_all()

    # 1. Create Default Users
    admin = User(username='admin', email='admin@vulntrack.local', role='Admin')
    admin.set_password('Admin@VulnTrack2026!')

    tester = User(username='student', email='student@college.edu', role='Tester')
    tester.set_password('Student@VulnTrack2026!')

    db.session.add_all([admin, tester])
    db.session.commit()

    # 2. Create Assessment 1: Baseline VAPT (Pre-Remediation)
    a1_start = date.today() - timedelta(days=30)
    a1_end = date.today() - timedelta(days=20)
    
    baseline = Assessment(
        name="Campus Student Portal & ERP — Baseline VAPT Lab",
        target_url="http://student-erp.campus.local",
        scope_notes="Authorized academic assessment in College Cybersecurity Lab. Scope includes Student login, Gradebook API, and Fees payment gateway in staging subnet.",
        tester="Aman Sharma (Roll: CS23B042)",
        start_date=a1_start,
        end_date=a1_end,
        status="Completed"
    )
    db.session.add(baseline)
    db.session.commit()

    # 3. Create Assessment 2: Retest VAPT (Post-Remediation)
    a2_start = date.today() - timedelta(days=10)
    a2_end = date.today() - timedelta(days=2)

    retest = Assessment(
        name="Campus Student Portal & ERP — Remediation Retest (Sem IV)",
        target_url="http://student-erp.campus.local",
        scope_notes="Verification retest of resolved security items identified in baseline assessment, retested during college lab session.",
        tester="Aman Sharma (Roll: CS23B042)",
        start_date=a2_start,
        end_date=a2_end,
        status="In Progress"
    )
    db.session.add(retest)
    db.session.commit()

    # Synthetic baseline findings
    baseline_findings_data = [
        {
            'title': "SQL Injection in Product Search API",
            'url': "https://shop-stage.vulntrack.local/api/v1/products/search",
            'method': "GET",
            'param': "query",
            'desc': "Unsanitized user input is concatenated directly into SQL query in catalog controller, allowing arbitrary database extraction.",
            'evidence': "GET /api/v1/products/search?query=book' UNION SELECT null,username,password_hash FROM users-- HTTP/1.1\nHTTP/1.1 200 OK\n[{\"username\": \"admin\", \"password_hash\": \"$2b$12$...\"}]",
            'sev': "Critical",
            'conf': "High",
            'cwe': "CWE-89",
            'owasp': "A05:2025 — Injection",
            'exploit': 100.0,
            'impact': 100.0,
            'exposure': 100.0,
            'tool': "Burp Suite",
            'rec': "Implement parameterized prepared statements with SQLAlchemy ORM query binding."
        },
        {
            'title': "Remote Code Execution via Insecure Deserialization",
            'url': "https://shop-stage.vulntrack.local/api/v1/cart/restore",
            'method': "POST",
            'param': "cart_token",
            'desc': "Server-side session cart deserialization accepts pickled binary payloads from client cookie, permitting arbitrary shell execution.",
            'evidence': "Payload: b'cos\\nsystem\\n(S\"id\"\\ntR.'\nResponse: uid=1001(www-data) gid=1001(www-data)",
            'sev': "Critical",
            'conf': "High",
            'cwe': "CWE-502",
            'owasp': "A08:2025 — Software or Data Integrity Failures",
            'exploit': 100.0,
            'impact': 100.0,
            'exposure': 100.0,
            'tool': "Burp Suite",
            'rec': "Never deserialize untrusted client objects. Use HMAC-signed JSON data structures."
        },
        {
            'title': "Bypassed Authorization on Merchant Order History (IDOR)",
            'url': "https://shop-stage.vulntrack.local/merchant/orders/view",
            'method': "GET",
            'param': "order_id",
            'desc': "Standard authenticated customer can view invoice and billing details of other merchants by altering the numeric order_id parameter.",
            'evidence': "GET /merchant/orders/view?order_id=9843 HTTP/1.1\nCookie: session=customer_session\nHTTP/1.1 200 OK\nReturns invoice containing customer PII and cardholder token.",
            'sev': "High",
            'conf': "High",
            'cwe': "CWE-639",
            'owasp': "A01:2025 — Broken Access Control",
            'exploit': 75.0,
            'impact': 75.0,
            'exposure': 70.0,
            'tool': "Manual",
            'rec': "Enforce server-side user-to-tenant authorization checks on all resource record lookups."
        },
        {
            'title': "Cross-Site Scripting (Reflected) in Review Feedback",
            'url': "https://shop-stage.vulntrack.local/reviews/submit",
            'method': "GET",
            'param': "rating_msg",
            'desc': "The rating feedback parameter is reflected without contextual HTML entity encoding, enabling session token hijacking.",
            'evidence': "Payload: <script>alert(document.domain)</script>\nEvidence: <div class='alert'>Your rating: <script>alert(document.domain)</script></div>",
            'sev': "High",
            'conf': "High",
            'cwe': "CWE-79",
            'owasp': "A05:2025 — Injection",
            'exploit': 75.0,
            'impact': 75.0,
            'exposure': 100.0,
            'tool': "OWASP ZAP",
            'rec': "Use auto-escaping templating engines (Jinja2) and establish a strict Content Security Policy."
        },
        {
            'title': "Missing Multi-Factor Authentication on Staff Portal",
            'url': "https://shop-stage.vulntrack.local/admin/login",
            'method': "POST",
            'param': "password",
            'desc': "Administrative dashboard authenticates privileged accounts with password only, without rate-limiting or mandatory 2FA.",
            'evidence': "Admin panel authenticated successfully without MFA prompt over public endpoint.",
            'sev': "High",
            'conf': "High",
            'cwe': "CWE-307",
            'owasp': "A07:2025 — Authentication Failures",
            'exploit': 45.0,
            'impact': 75.0,
            'exposure': 70.0,
            'tool': "Manual",
            'rec': "Mandate TOTP/FIDO2 MFA for all administrative roles and apply progressive delay rate limiting."
        },
        {
            'title': "Cleartext HTTP Transmission of Customer Credentials",
            'url': "https://shop-stage.vulntrack.local/api/v1/auth/token",
            'method': "POST",
            'param': "password",
            'desc': "Authentication endpoint accepts unencrypted HTTP connections without enforcing HSTS or HTTPS redirection.",
            'evidence': "POST http://shop-stage.vulntrack.local/api/v1/auth/token\nPayload: {\"user\":\"demo\",\"pass\":\"secret123\"}",
            'sev': "Medium",
            'conf': "High",
            'cwe': "CWE-319",
            'owasp': "A04:2025 — Cryptographic Failures",
            'exploit': 45.0,
            'impact': 50.0,
            'exposure': 100.0,
            'tool': "OWASP ZAP",
            'rec': "Enforce Strict-Transport-Security (HSTS) with max-age=31536000 and redirect all port 80 traffic to TLS."
        },
        {
            'title': "Vulnerable Third-Party JavaScript Dependency (lodash 4.17.15)",
            'url': "https://shop-stage.vulntrack.local/static/js/vendor/lodash.js",
            'method': "GET",
            'param': None,
            'desc': "Outdated client library vulnerable to Prototype Pollution (CVE-2020-8203).",
            'evidence': "lodash.VERSION == '4.17.15' identified in public assets bundle.",
            'sev': "Medium",
            'conf': "High",
            'cwe': "CWE-1395",
            'owasp': "A03:2025 — Software Supply Chain Failures",
            'exploit': 45.0,
            'impact': 50.0,
            'exposure': 70.0,
            'tool': "OWASP ZAP",
            'rec': "Update lodash dependency to version >= 4.17.21 in package.json."
        },
        {
            'title': "Sensitive Session Cookie Missing 'HttpOnly' and 'Secure' Flags",
            'url': "https://shop-stage.vulntrack.local/login",
            'method': "POST",
            'param': "session_token",
            'desc': "Session identifier cookie can be accessed by client-side scripts and transmitted over plain HTTP.",
            'evidence': "Set-Cookie: session_token=vt_sess_778129; Path=/",
            'sev': "Medium",
            'conf': "High",
            'cwe': "CWE-1004",
            'owasp': "A02:2025 — Security Misconfiguration",
            'exploit': 45.0,
            'impact': 50.0,
            'exposure': 70.0,
            'tool': "OWASP ZAP",
            'rec': "Configure session cookie attributes: HttpOnly; Secure; SameSite=Lax."
        },
        {
            'title': "Unprotected Swagger API Documentation & Schema Exposure",
            'url': "https://shop-stage.vulntrack.local/api/docs",
            'method': "GET",
            'param': None,
            'desc': "Interactive OpenAPI schema and internal API routes exposed to anonymous internet visitors.",
            'evidence': "HTTP 200 OK rendering Swagger UI with private endpoints like /internal/debug/cache-dump.",
            'sev': "Low",
            'conf': "High",
            'cwe': "CWE-200",
            'owasp': "A02:2025 — Security Misconfiguration",
            'exploit': 15.0,
            'impact': 25.0,
            'exposure': 100.0,
            'tool': "Manual",
            'rec': "Restrict Swagger UI and OpenAPI documentation to authenticated internal developer networks."
        },
        {
            'title': "Missing Anti-Clickjacking X-Frame-Options Header",
            'url': "https://shop-stage.vulntrack.local/checkout",
            'method': "GET",
            'param': None,
            'desc': "Payment frame does not restrict framing, exposing users to UI redressing attacks.",
            'evidence': "Response headers lack X-Frame-Options and Content-Security-Policy frame-ancestors directive.",
            'sev': "Low",
            'conf': "High",
            'cwe': "CWE-1021",
            'owasp': "A02:2025 — Security Misconfiguration",
            'exploit': 15.0,
            'impact': 25.0,
            'exposure': 100.0,
            'tool': "OWASP ZAP",
            'rec': "Add 'X-Frame-Options: SAMEORIGIN' header to all HTML responses."
        },
        {
            'title': "Detailed Exception Stack Trace Leak in Error Handler",
            'url': "https://shop-stage.vulntrack.local/api/debug/error",
            'method': "GET",
            'param': None,
            'desc': "Application outputs Python tracebacks and internal server directory structures on 500 errors.",
            'evidence': "Traceback (most recent call last):\n  File '/app/controllers/checkout.py', line 89 in process\nZeroDivisionError: division by zero",
            'sev': "Low",
            'conf': "High",
            'cwe': "CWE-209",
            'owasp': "A10:2025 — Mishandling of Exceptional Conditions",
            'exploit': 15.0,
            'impact': 25.0,
            'exposure': 70.0,
            'tool': "Manual",
            'rec': "Disable DEBUG mode in production configuration and display generic error templates."
        },
        {
            'title': "Web Server Version Banner Disclosure (nginx/1.18.0)",
            'url': "https://shop-stage.vulntrack.local/",
            'method': "HEAD",
            'param': None,
            'desc': "HTTP response header reveals explicit web server banner and version information.",
            'evidence': "Server: nginx/1.18.0 (Ubuntu)",
            'sev': "Informational",
            'conf': "High",
            'cwe': "CWE-200",
            'owasp': "A02:2025 — Security Misconfiguration",
            'exploit': 15.0,
            'impact': 10.0,
            'exposure': 70.0,
            'tool': "OWASP ZAP",
            'rec': "Set 'server_tokens off;' in nginx.conf."
        }
    ]

    saved_baseline_objects = []

    # Insert baseline findings
    for item in baseline_findings_data:
        r = calculate_risk_score(
            severity=item['sev'],
            exploitability=item['exploit'],
            business_impact=item['impact'],
            exposure=item['exposure']
        )
        fp = generate_finding_fingerprint(
            title=item['title'],
            affected_url=item['url'],
            http_method=item['method'],
            parameter=item['param'],
            cwe_id=item['cwe']
        )
        f = VulnerabilityFinding(
            assessment_id=baseline.id,
            title=item['title'],
            affected_url=item['url'],
            http_method=item['method'],
            parameter=item['param'],
            description=item['desc'],
            evidence=item['evidence'],
            severity=item['sev'],
            confidence=item['conf'],
            cwe_id=item['cwe'],
            owasp_category=item['owasp'],
            owasp_year="2025",
            exploitability_level=item['exploit'],
            business_impact=item['impact'],
            exposure_level=item['exposure'],
            risk_score=r['final_score'],
            risk_priority=r['priority'],
            remediation_recommendation=item['rec'],
            remediation_status="Open",
            source_tool=item['tool'],
            fingerprint_hash=fp,
            duplicate_group_id=fp[:12],
            is_duplicate=False,
            first_discovered_date=datetime.utcnow() - timedelta(days=25),
            last_observed_date=datetime.utcnow() - timedelta(days=20)
        )
        db.session.add(f)
        saved_baseline_objects.append((item, f))

    db.session.commit()

    # Now populate Retest Assessment to demonstrate before-and-after comparison!
    # Statuses in Retest:
    # - Fixed items: SQL Injection, RCE, IDOR, Reflected XSS, Cookie flags, Stack trace leak
    # - Persisting open items: MFA missing, Outdated lodash
    # - Accepted risk item: Swagger API documentation (business accepted for staging environment)
    # - New item introduced in retest: CORS misconfiguration
    for item, b_obj in saved_baseline_objects:
        # Determine retest fate
        if item['title'] in [
            "SQL Injection in Product Search API",
            "Remote Code Execution via Insecure Deserialization",
            "Bypassed Authorization on Merchant Order History (IDOR)",
            "Cross-Site Scripting (Reflected) in Review Feedback",
            "Sensitive Session Cookie Missing 'HttpOnly' and 'Secure' Flags",
            "Detailed Exception Stack Trace Leak in Error Handler"
        ]:
            status = "Fixed"
            retest_res = "Passed / Remediated"
            retest_notes = "Verified by security tester via automated fuzzer and manual payload replay. Patched successfully."
            fixed_date = datetime.utcnow() - timedelta(days=5)
        elif item['title'] == "Unprotected Swagger API Documentation & Schema Exposure":
            status = "Accepted Risk"
            retest_res = "Partially Remediated"
            retest_notes = "Swagger UI restricted to staging subnet; public access blocked."
            fixed_date = None
        else:
            status = "Open"
            retest_res = "Failed / Persists"
            retest_notes = "Issue persists in current deployment build; pending developer sprint."
            fixed_date = None

        r = calculate_risk_score(
            severity=item['sev'],
            exploitability=item['exploit'],
            business_impact=item['impact'],
            exposure=item['exposure']
        )
        fp = b_obj.fingerprint_hash

        retest_f = VulnerabilityFinding(
            assessment_id=retest.id,
            title=item['title'],
            affected_url=item['url'],
            http_method=item['method'],
            parameter=item['param'],
            description=item['desc'],
            evidence=item['evidence'],
            severity=item['sev'],
            confidence=item['conf'],
            cwe_id=item['cwe'],
            owasp_category=item['owasp'],
            owasp_year="2025",
            exploitability_level=item['exploit'],
            business_impact=item['impact'],
            exposure_level=item['exposure'],
            risk_score=r['final_score'],
            risk_priority=r['priority'],
            remediation_recommendation=item['rec'],
            remediation_status=status,
            retest_result=retest_res,
            retest_notes=retest_notes,
            retest_date=datetime.utcnow() - timedelta(days=4),
            accepted_risk_justification="Staging developer team requires schema access; staging environment is protected by perimeter WAF." if status == "Accepted Risk" else None,
            fixed_at=fixed_date,
            source_tool=item['tool'],
            fingerprint_hash=fp,
            duplicate_group_id=fp[:12],
            is_duplicate=False,
            first_discovered_date=b_obj.first_discovered_date,
            last_observed_date=datetime.utcnow() - timedelta(days=2)
        )
        db.session.add(retest_f)

    # Add 1 newly introduced finding in the retest assessment!
    new_cors_r = calculate_risk_score(severity="High", exploitability=75.0, business_impact=75.0, exposure=100.0)
    new_fp = generate_finding_fingerprint("Overly Permissive CORS Access-Control-Allow-Origin: *", "https://shop-stage.vulntrack.local/api/v1/auth/user", "OPTIONS", None, "CWE-942")
    new_finding = VulnerabilityFinding(
        assessment_id=retest.id,
        title="Overly Permissive CORS Access-Control-Allow-Origin: *",
        affected_url="https://shop-stage.vulntrack.local/api/v1/auth/user",
        http_method="OPTIONS",
        description="During the retest sprint, developers enabled Access-Control-Allow-Origin: * on authenticated user endpoints with credentials allowed.",
        evidence="HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
        severity="High",
        confidence="High",
        cwe_id="CWE-942",
        owasp_category="A01:2025 — Broken Access Control",
        owasp_year="2025",
        exploitability_level=75.0,
        business_impact=75.0,
        exposure_level=100.0,
        risk_score=new_cors_r['final_score'],
        risk_priority=new_cors_r['priority'],
        remediation_recommendation="Restrict allowed CORS origins to trusted domain whitelists and disable credentials on wildcard endpoints.",
        remediation_status="Open",
        source_tool="Manual",
        fingerprint_hash=new_fp,
        duplicate_group_id=new_fp[:12],
        is_duplicate=False,
        first_discovered_date=datetime.utcnow() - timedelta(days=2),
        last_observed_date=datetime.utcnow() - timedelta(days=2)
    )
    db.session.add(new_finding)

    # 4. Audit Log Entries
    logs = [
        AuditLog(username='admin', action_type='INITIALIZE_DATABASE', details="Initialized database schemas and seeded cybersecurity lab demo records."),
        AuditLog(username='student', action_type='ASSESSMENT_CREATE', target_id=str(baseline.id), details=f"Created baseline assessment '{baseline.name}' for college lab evaluation."),
        AuditLog(username='student', action_type='IMPORT_ZAP', target_id=str(baseline.id), details="Imported baseline vulnerability findings from OWASP ZAP scan export."),
        AuditLog(username='student', action_type='ASSESSMENT_CREATE', target_id=str(retest.id), details=f"Created remediation retest assessment '{retest.name}'"),
        AuditLog(username='student', action_type='RETEST_RECORD', target_id=str(retest.id), details="Recorded lab retest outcomes and verified patches for resolved vulnerabilities.")
    ]
    db.session.add_all(logs)
    db.session.commit()


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        populate_demo_data()
        print("[OK] Demo data successfully seeded!")
