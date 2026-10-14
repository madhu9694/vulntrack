import urllib.request
import urllib.parse
import http.cookiejar
import re

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. Fetch Login to get CSRF token
resp = opener.open('http://127.0.0.1:5000/login')
html = resp.read().decode('utf-8')
csrf_match = re.search(r'name=["\']csrf_token["\'].*?value=["\']([^"\']+)["\']', html, re.DOTALL)
if not csrf_match:
    csrf_match = re.search(r'value=["\']([^"\']+)["\']', html)
csrf_token = csrf_match.group(1)
print(f"[OK] CSRF token obtained: {csrf_token[:10]}...")

# 2. Authenticate
login_data = urllib.parse.urlencode({
    'username': 'admin',
    'password': 'Admin@VulnTrack2026!',
    'csrf_token': csrf_token
}).encode('utf-8')
login_resp = opener.open('http://127.0.0.1:5000/login', data=login_data)
dashboard_html = login_resp.read().decode('utf-8')
assert 'VAPT Security Dashboard' in dashboard_html, "Dashboard title missing"
print("[OK] Login successful and redirected to Dashboard")

# 3. Check Assessments
assess_resp = opener.open('http://127.0.0.1:5000/assessments/')
assess_html = assess_resp.read().decode('utf-8')
assert 'Security Assessments' in assess_html
print("[OK] Assessments page loaded and verified")

# 4. Check Vulnerabilities
vuln_resp = opener.open('http://127.0.0.1:5000/vulnerabilities/')
vuln_html = vuln_resp.read().decode('utf-8')
assert 'Vulnerability Repository' in vuln_html
print("[OK] Vulnerabilities repository loaded and verified")

# 5. Check Remediation Tracker
rem_resp = opener.open('http://127.0.0.1:5000/remediation/')
rem_html = rem_resp.read().decode('utf-8')
assert 'Remediation Tracker' in rem_html
print("[OK] Remediation tracker loaded and verified")

# 6. Check Assessment Comparison
comp_resp = opener.open('http://127.0.0.1:5000/comparison/?baseline_id=1&retest_id=2')
comp_html = comp_resp.read().decode('utf-8')
assert 'Side-by-Side Scope Metrics' in comp_html
assert 'Risk Score Reduction' in comp_html
print("[OK] Before-and-after comparison loaded and verified")

# 7. Download PDF Report
pdf_resp = opener.open('http://127.0.0.1:5000/reports/download/1')
pdf_bytes = pdf_resp.read()
assert pdf_bytes.startswith(b'%PDF-'), "PDF magic header missing"
print(f"[OK] VAPT PDF Report generated successfully ({len(pdf_bytes)} bytes)")

print("\n>>> ALL END-TO-END WORKFLOWS VERIFIED SUCCESSFULLY! <<<")
