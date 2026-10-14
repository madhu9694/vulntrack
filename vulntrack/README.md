# VulnTrack — VAPT Vulnerability Management & Risk Prioritization System

**Course:** B.Tech / B.Sc Computer Science & Engineering (2nd Year)  
**Subject:** Cybersecurity & Ethical Hacking Laboratory  
**Project Title:** VulnTrack — VAPT Vulnerability Management & Risk Prioritization Dashboard  
**Developed By:** Aman Sharma (Student Pentester — Roll No: CS23B042)  
**Academic Supervisor / Lab Evaluation:** Department of Computer Science & Engineering  

---

> **CRITICAL ETHICAL NOTICE & ACADEMIC DISCLAIMER:**  
> This platform is developed strictly for educational and defensive cybersecurity laboratory assessments. Testing must only be conducted against authorized targets, deliberately vulnerable applications (such as OWASP Juice Shop, DVWA), or systems for which explicit written authorization has been granted.

---

## 1. Project Overview & Objective

During our 2nd year cybersecurity lab sessions, we frequently run vulnerability assessment tools like **OWASP ZAP** and intercept HTTP traffic using **Burp Suite Community Edition**. However, analyzing hundreds of raw alerts from automated scanners and manual notes is overwhelming. Standard tools often produce duplicate findings, lack business risk context, and offer no easy way to track whether a developer actually fixed a reported bug.

**VulnTrack** solves this problem by providing a centralized web dashboard that helps student security testers and ethical hackers:
1. **Manage Assessments:** Create and organize authorized penetration testing scopes.
2. **Import Automated Scans:** Safely parse OWASP ZAP exported JSON and XML reports.
3. **Log Manual Findings:** Record and validate findings discovered through Burp Suite.
4. **Map to OWASP Top 10:2025:** Suggest categories under the latest 2025 security taxonomy.
5. **Prioritize via Transparent Risk Scores:** Compute an explainable **40/25/25/10** risk score.
6. **Detect Duplicate Endpoints:** Group recurring scan alerts using SHA-256 fingerprinting.
7. **Track Remediation:** Monitor vulnerabilities through Open $\rightarrow$ In Progress $\rightarrow$ Retest Pending $\rightarrow$ Fixed / Accepted Risk.
8. **Compare Scans (Before vs. After):** Measure remediation effectiveness and net percentage risk reduction.
9. **Generate VAPT Reports:** Produce audit-ready PDF reports via ReportLab.

---

## 2. System Architecture

```
Authorized Lab Target (e.g. Campus Student ERP / OWASP Juice Shop)
                            ↓
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│        OWASP ZAP Automated Scan      │     │    Burp Suite Manual Verification    │
│         (Exported JSON / XML)        │     │       (Proxy Intercept & PoC)        │
└──────────────────┬───────────────────┘     └──────────────────┬───────────────────┘
                   │                                            │
                   └─────────────────────┬──────────────────────┘
                                         ↓
                     ┌──────────────────────────────────────┐
                     │    Vulnerability Analysis Engine     │
                     │  • SHA-256 Fingerprint Deduplication │
                     │  • OWASP Top 10:2025 Rule Mapper     │
                     │  • 40/25/25/10 Explainable Risk      │
                     │  • Remediation & Retest Logic        │
                     └───────────────────┬──────────────────┘
                                         ↓
                               SQLite Database (ORM)
                                         ↓
     ┌───────────────────────────────────┴───────────────────────────────────┐
     ↓                                   ↓                                   ↓
Security Dashboard               Remediation Kanban               Downloadable PDF
(Chart.js Analytics)             (Retests & Accepted Risk)         VAPT Reports
```

---

## 3. Technology Stack

- **Backend:** Python 3.10+ with Flask 3.0.3
- **ORM & Database:** SQLAlchemy 2.0+ via Flask-SQLAlchemy with SQLite (zero complex server setup required)
- **Forms & Validation:** Flask-WTF with server-side CSRF tokens and validation rules
- **Security & Authentication:** Flask-Login with Werkzeug password hashing
- **XML Parsing:** `defusedxml` (safeguards against XXE / entity expansion attacks)
- **Frontend:** HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons
- **Visualizations:** Chart.js 4.4
- **PDF Generation:** ReportLab 4.2
- **Testing:** pytest 8.2 (26 automated test cases)

---

## 4. Setup and Installation (Windows PowerShell / VS Code)

### Step 1: Open VS Code Terminal in Project Directory
```powershell
cd C:\Users\Admin\.gemini\antigravity\scratch\vulntrack
```

### Step 2: Create and Activate Virtual Environment
```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If execution policy restricts running scripts: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Initialize Database and Populate Demo Data
Run the demo initialization script:
```powershell
python init_demo.py
```
*This populates a realistic Campus Student Portal Baseline Assessment and a Post-Remediation Retest with 25 vulnerability records.*

### Step 5: Start the Local Development Server
```powershell
python run.py
```
Open your web browser and navigate to: **`http://127.0.0.1:5000`**

### Step 6: Log In with Student or Admin Credentials
- **Student Pentester Account:**
  - **Username:** `student`
  - **Password:** `Student@VulnTrack2026!`
- **Administrator Account:**
  - **Username:** `admin`
  - **Password:** `Admin@VulnTrack2026!`

---

## 5. Running Automated Tests

Run the full pytest suite:
```powershell
pytest -v
```
Run the live HTTP end-to-end integration test against the running server:
```powershell
python tests/verify_e2e.py
```

---

## 6. Transparent Risk Scoring Engine (Formula Explained)

In academic projects, examiners often criticize black-box risk algorithms. VulnTrack uses a deterministic, transparent formula normalized between **0.00 and 100.00**:

$$\text{Risk Score} = (\text{Severity} \times 0.40) + (\text{Exploitability} \times 0.25) + (\text{Business Impact} \times 0.25) + (\text{Exposure} \times 0.10)$$

### Component Weights & Scales

1. **Severity (40% Weight):**
   - Critical: 100.0
   - High: 80.0
   - Medium: 55.0
   - Low: 30.0
   - Informational: 10.0

2. **Exploitability (25% Weight):**
   - Trivial / Public Exploit (100.0): Automated tool or public exploit script exists.
   - Functional PoC Available (75.0): Proof of concept verified in lab.
   - Moderate / Special Preconditions (45.0): Requires authenticated non-default setup.
   - Theoretical / Very Difficult (15.0): Complex timing or rare preconditions.

3. **Business Impact (25% Weight):**
   - Critical (100.0): Complete database takeover, student data exfiltration.
   - High (75.0): Unauthorized grade tampering or account takeover.
   - Medium (50.0): Limited non-confidential information leak.
   - Low (25.0): Minor internal error disclosure.
   - Negligible (10.0): Informational / cosmetic.

4. **Exposure Level (10% Weight):**
   - Public Internet / Unauthenticated (100.0): Open to any remote user.
   - Public Internet / Authenticated User (70.0): Accessible to student accounts.
   - Internal Campus Network / VPN (40.0): Restricted to campus subnet.
   - Restricted Admin Segment / Localhost (15.0): Isolated management plane.

### Prioritization Bands
- **Critical Priority:** 80.00 – 100.00
- **High Priority:** 60.00 – 79.99
- **Medium Priority:** 40.00 – 59.99
- **Low Priority:** 0.00 – 39.99

---

## 7. Viva Voce & Practical Exam Guide (Frequently Asked Questions by Professors)

Here are the most common questions external examiners and professors ask during project evaluations, along with clear answers:

### Q1: Why create a custom 40/25/25/10 formula instead of just displaying the CVSS Base Score?
**Student Answer:**  
> *"Sir/Ma'am, the CVSS Base Score measures only the intrinsic technical severity of a vulnerability in isolation. However, in real-world application security, a High-severity flaw located on an internal development machine behind a VPN poses much less immediate risk than a High-severity flaw on a public, unauthenticated student login page. Our formula combines technical severity (40%) with exploitability (25%), business impact (25%), and network exposure (10%) to provide actionable triage priority."*

### Q2: How does your duplicate detection engine prevent false positives?
**Student Answer:**  
> *"Rather than relying merely on vulnerability titles, our deduplication service normalizes the title, affected URL (normalizing casing, stripping trailing slashes, and sorting query parameters), HTTP method, parameter name, and CWE ID into a single string, and hashes it using SHA-256. If two findings have different vulnerable parameters (e.g. `?id=1` vs `?user=admin`), they generate distinct fingerprints. Crucially, we never delete duplicates automatically; we link them to the original finding so the security tester has the final authority."*

### Q3: When comparing a baseline scan and a retest, how do you handle a vulnerability that disappeared in the second scan?
**Student Answer:**  
> *"Automated vulnerability scanners can miss endpoints due to crawling timeouts, session logouts, or rate limiting. Therefore, if a finding was present in the baseline but not observed in the retest, our comparison engine does NOT assume it is fixed. It classifies it as 'Not Observed in Retest Scan' until a human tester explicitly validates the patch and marks it as 'Fixed'."*

### Q4: How do you prevent XML External Entity (XXE) injection when importing ZAP XML reports?
**Student Answer:**  
> *"Standard Python `xml.etree` is susceptible to XXE attacks where malicious XML files could read local system files or cause Denial of Service. We used `defusedxml.ElementTree`, which disables external entity resolution and DTD expansions, completely protecting the application."*

### Q5: How do you prevent Stored XSS from vulnerability scan evidence?
**Student Answer:**  
> *"ZAP alerts often contain raw HTML payloads like `<script>alert(1)</script>` inside attack parameters and descriptions. In `services/zap_importer.py`, we strip all HTML tags using regex and unescape entities safely. Furthermore, Jinja2 auto-escapes all template variables, and in ReportLab PDF generation, we pass all strings through `html.escape()`."*

---

## 8. Suggested Project Demonstration Script (Viva Presentation Steps)

Follow these steps during your live lab demonstration:

1. **Sign-In Screen:**  
   Navigate to `http://127.0.0.1:5000/login`. Explain session security, CSRF protection, and log in with `student` / `Student@VulnTrack2026!`.
2. **Dashboard Overview:**  
   Highlight the 6 summary cards, the Severity Doughnut chart, OWASP Top 10:2025 bar chart, and Risk Priority histogram. Demonstrate the Scope Filter dropdown.
3. **ZAP Report Import:**  
   Go to **Assessments** $\rightarrow$ *Campus Student Portal Baseline* $\rightarrow$ Click **Import ZAP Report**. Upload `sample_reports/sample_zap_report.json` to show automated parsing and duplicate grouping.
4. **Manual Burp Suite Finding:**  
   Click **Add Finding**. Fill in an IDOR finding validated in Burp Suite. Show how changing Exploitability and Business Impact dynamically recalculates the prioritization score.
5. **Finding Detail & Mathematical Trace:**  
   Open any finding detail page. Show the professor the **Risk Score Breakdown** card displaying the exact mathematical calculation trace.
6. **Remediation Tracker:**  
   Open **Remediation Tracker**. Point out the completion progress bar ($%$) and the urgent critical/high open issues table. Update a finding to **Fixed** with a retest outcome.
7. **Before-and-After Comparison:**  
   Open **Before vs After**. Compare Assessment #1 (Baseline) with Assessment #2 (Retest). Highlight the **Risk Score Reduction %** and the categorized lists of fixed, persisting, and new issues.
8. **PDF Report Generation:**  
   Click **VAPT Reports** $\rightarrow$ **Generate PDF**. Open the downloaded PDF in your viewer and showcase the student project cover page, executive summary, methodology, and page numbers.
9. **Test Suite Execution:**  
   Open the terminal and run `pytest -v` to prove that all 26 unit tests pass with 100% success.
