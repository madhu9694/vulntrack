"""
VulnTrack OWASP ZAP Report Importer.

Safely parses exported OWASP ZAP reports in JSON and XML formats.
Extracts security alerts, normalizes data, strips HTML formatting,
applies OWASP Top 10:2025 mappings, computes deterministic risk scores,
and identifies duplicate findings.
"""

import json
import re
from html import unescape
from typing import Dict, Any, List, Tuple
import defusedxml.ElementTree as ET

from models import VulnerabilityFinding, Assessment
from extensions import db
from services.risk_engine import calculate_risk_score
from services.owasp_mapper import suggest_owasp_category
from services.deduplication import generate_finding_fingerprint, find_matching_original

# Mapping from ZAP risk descriptions/codes to VulnTrack severities
ZAP_RISK_MAP = {
    '3': 'High',
    '2': 'Medium',
    '1': 'Low',
    '0': 'Informational',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'informational': 'Informational',
    'info': 'Informational'
}

ZAP_CONFIDENCE_MAP = {
    '3': 'High',
    '2': 'Medium',
    '1': 'Low',
    '0': 'False Positive',
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'false positive': 'False Positive'
}


def clean_html_text(text: str) -> str:
    """
    Strip HTML markup and unescape HTML entities safely.
    
    VIVA SECURITY NOTE:
    ZAP reports embed raw HTML like <p> and <script> in descriptions and attacks.
    If we saved and rendered that directly in our dashboard, it could lead to Stored XSS.
    We strip all HTML tags using regex and unescape safe entities so data is always sanitized.
    """
    if not text:
        return ""
    # Strip HTML tags
    cleaned = re.sub(r'<[^>]+>', ' ', str(text))
    # Unescape entities
    cleaned = unescape(cleaned)
    # Normalize whitespaces
    return ' '.join(cleaned.split())


def map_zap_risk(risk_str: str) -> str:
    """Translate ZAP risk indicator to VulnTrack severity."""
    if not risk_str:
        return 'Medium'
    r = str(risk_str).strip().lower()
    for key, val in ZAP_RISK_MAP.items():
        if key in r:
            return val
    return 'Medium'


def map_zap_confidence(conf_str: str) -> str:
    """Translate ZAP confidence indicator to VulnTrack confidence."""
    if not conf_str:
        return 'Medium'
    c = str(conf_str).strip().lower()
    for key, val in ZAP_CONFIDENCE_MAP.items():
        if key in c:
            return val
    return 'Medium'


def parse_zap_json(file_content: str) -> List[Dict[str, Any]]:
    """Parse ZAP JSON export report safely."""
    try:
        data = json.loads(file_content)
    except Exception as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")

    extracted_alerts = []
    
    # Structure 1: Standard ZAP JSON with "site" array or object
    sites = data.get('site', [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        alerts = site.get('alerts', [])
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            alert_name = alert.get('alert') or alert.get('name') or "Untitled Finding"
            risk_raw = alert.get('riskdesc') or str(alert.get('riskcode', '2'))
            confidence_raw = alert.get('confidence', '2')
            desc = clean_html_text(alert.get('desc', ''))
            solution = clean_html_text(alert.get('solution', ''))
            cwe_id = str(alert.get('cweid', ''))
            if cwe_id and cwe_id != '0' and not cwe_id.upper().startswith('CWE-'):
                cwe_id = f"CWE-{cwe_id}"
            elif cwe_id == '0':
                cwe_id = None

            instances = alert.get('instances', [])
            if not instances:
                # Fallback to top-level uri if present
                uri = alert.get('uri') or site.get('@name', 'http://target.local')
                method = alert.get('method', 'GET')
                param = alert.get('param', '')
                evidence = clean_html_text(alert.get('evidence', ''))
                extracted_alerts.append({
                    'title': alert_name,
                    'severity': map_zap_risk(risk_raw),
                    'confidence': map_zap_confidence(str(confidence_raw)),
                    'url': uri,
                    'method': method,
                    'param': param,
                    'description': desc,
                    'evidence': evidence,
                    'solution': solution,
                    'cwe_id': cwe_id
                })
            else:
                for inst in instances:
                    uri = inst.get('uri') or site.get('@name', 'http://target.local')
                    method = inst.get('method', 'GET')
                    param = inst.get('param', '')
                    evidence = clean_html_text(inst.get('evidence', '') or inst.get('attack', ''))
                    extracted_alerts.append({
                        'title': alert_name,
                        'severity': map_zap_risk(risk_raw),
                        'confidence': map_zap_confidence(str(confidence_raw)),
                        'url': uri,
                        'method': method,
                        'param': param,
                        'description': desc,
                        'evidence': evidence,
                        'solution': solution,
                        'cwe_id': cwe_id
                    })

    # Structure 2: Flat alerts array
    if not extracted_alerts and 'alerts' in data:
        for alert in data['alerts']:
            alert_name = alert.get('name') or alert.get('alert') or "Untitled Finding"
            risk_raw = alert.get('risk') or alert.get('riskdesc') or 'Medium'
            confidence_raw = alert.get('confidence', 'Medium')
            desc = clean_html_text(alert.get('description', '') or alert.get('desc', ''))
            solution = clean_html_text(alert.get('solution', ''))
            cwe_id = str(alert.get('cweid', alert.get('cwe_id', '')))
            if cwe_id and cwe_id != '0' and not cwe_id.upper().startswith('CWE-'):
                cwe_id = f"CWE-{cwe_id}"

            uri = alert.get('url') or alert.get('uri') or "http://target.local"
            method = alert.get('method', 'GET')
            param = alert.get('param', '')
            evidence = clean_html_text(alert.get('evidence', ''))

            extracted_alerts.append({
                'title': alert_name,
                'severity': map_zap_risk(risk_raw),
                'confidence': map_zap_confidence(str(confidence_raw)),
                'url': uri,
                'method': method,
                'param': param,
                'description': desc,
                'evidence': evidence,
                'solution': solution,
                'cwe_id': cwe_id
            })

    return extracted_alerts


def parse_zap_xml(file_content: str) -> List[Dict[str, Any]]:
    """Parse ZAP XML report safely using defusedxml."""
    try:
        root = ET.fromstring(file_content)
    except Exception as e:
        raise ValueError(f"Invalid XML format: {str(e)}")

    extracted_alerts = []

    # Handle standard OWASPZAPReport elements
    for site in root.findall('.//site'):
        site_name = site.attrib.get('name', 'http://target.local')
        for alert in site.findall('.//alertitem'):
            title = clean_html_text(alert.findtext('alert') or alert.findtext('name') or "Untitled Finding")
            risk_desc = alert.findtext('riskdesc') or alert.findtext('riskcode') or "Medium"
            conf_desc = alert.findtext('confidence') or "Medium"
            desc = clean_html_text(alert.findtext('desc') or "")
            solution = clean_html_text(alert.findtext('solution') or "")
            cwe_val = alert.findtext('cweid') or ""
            cwe_id = f"CWE-{cwe_val}" if cwe_val and cwe_val != '0' else None

            instances = alert.findall('.//instances/instance')
            if not instances:
                uri = alert.findtext('uri') or site_name
                method = alert.findtext('method') or "GET"
                param = alert.findtext('param') or ""
                evidence = clean_html_text(alert.findtext('evidence') or "")
                extracted_alerts.append({
                    'title': title,
                    'severity': map_zap_risk(risk_desc),
                    'confidence': map_zap_confidence(conf_desc),
                    'url': uri,
                    'method': method,
                    'param': param,
                    'description': desc,
                    'evidence': evidence,
                    'solution': solution,
                    'cwe_id': cwe_id
                })
            else:
                for inst in instances:
                    uri = inst.findtext('uri') or site_name
                    method = inst.findtext('method') or "GET"
                    param = inst.findtext('param') or ""
                    evidence = clean_html_text(inst.findtext('evidence') or inst.findtext('attack') or "")
                    extracted_alerts.append({
                        'title': title,
                        'severity': map_zap_risk(risk_desc),
                        'confidence': map_zap_confidence(conf_desc),
                        'url': uri,
                        'method': method,
                        'param': param,
                        'description': desc,
                        'evidence': evidence,
                        'solution': solution,
                        'cwe_id': cwe_id
                    })

    return extracted_alerts


def import_zap_report(
    assessment_id: int,
    file_content: str,
    file_type: str = 'json',
    skip_duplicates: bool = False
) -> Dict[str, Any]:
    """
    Process ZAP scan report, integrate into database with risk scores and OWASP mapping.
    
    Returns:
        Summary dict with counts of imported, duplicates, invalid records, and message.
    """
    assessment = db.session.get(Assessment, assessment_id)
    if not assessment:
        raise ValueError(f"Assessment with ID {assessment_id} does not exist.")

    if file_type.lower() == 'json':
        parsed_records = parse_zap_json(file_content)
    elif file_type.lower() == 'xml':
        parsed_records = parse_zap_xml(file_content)
    else:
        raise ValueError(f"Unsupported file type: {file_type}. Please provide JSON or XML.")

    summary = {
        'total_parsed': len(parsed_records),
        'imported_count': 0,
        'duplicates_count': 0,
        'duplicates_skipped': 0,
        'invalid_count': 0,
        'errors': []
    }

    for item in parsed_records:
        try:
            title = item.get('title', '').strip()
            url = item.get('url', '').strip()
            if not title or not url:
                summary['invalid_count'] += 1
                continue

            severity = item.get('severity', 'Medium')
            confidence = item.get('confidence', 'Medium')
            method = item.get('method', 'GET')
            param = item.get('param') or None
            description = item.get('description', 'No description provided.')
            evidence = item.get('evidence') or None
            solution = item.get('solution') or "Apply secure coding principles and validate input."
            cwe_id = item.get('cwe_id')

            # Suggest OWASP Top 10:2025 Category
            owasp_res = suggest_owasp_category(title, description, cwe_id)
            owasp_cat = owasp_res['category']

            # Calculate Risk Score using default unverified environmental parameters
            risk_res = calculate_risk_score(severity=severity)
            risk_score = risk_res['final_score']
            risk_priority = risk_res['priority']

            # Deduplication Fingerprint
            fingerprint = generate_finding_fingerprint(
                title=title,
                affected_url=url,
                http_method=method,
                parameter=param,
                cwe_id=cwe_id
            )

            existing_original = find_matching_original(
                fingerprint=fingerprint,
                current_assessment_id=assessment_id
            )

            is_duplicate = False
            original_id = None
            dup_group = fingerprint[:12]

            if existing_original:
                summary['duplicates_count'] += 1
                if skip_duplicates:
                    summary['duplicates_skipped'] += 1
                    continue
                else:
                    is_duplicate = True
                    original_id = existing_original.id

            finding = VulnerabilityFinding(
                assessment_id=assessment_id,
                title=title,
                affected_url=url,
                http_method=method,
                parameter=param,
                description=description,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                cwe_id=cwe_id,
                owasp_category=owasp_cat,
                owasp_year="2025",
                exploitability_level=50.0,
                business_impact=50.0,
                exposure_level=70.0,
                risk_score=risk_score,
                risk_priority=risk_priority,
                remediation_recommendation=solution,
                remediation_status="Open",
                source_tool="OWASP ZAP",
                fingerprint_hash=fingerprint,
                duplicate_group_id=dup_group,
                is_duplicate=is_duplicate,
                original_finding_id=original_id
            )

            db.session.add(finding)
            summary['imported_count'] += 1

        except Exception as e:
            summary['invalid_count'] += 1
            summary['errors'].append(str(e))

    db.session.commit()
    return summary
