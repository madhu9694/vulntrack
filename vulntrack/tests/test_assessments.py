"""
Unit tests for Assessment Management Routes.
"""

from models import Assessment
from extensions import db


def test_assessment_crud_lifecycle(auth_client, app):
    """Test full assessment create, read, update, and delete workflow."""
    # 1. Create Assessment
    res = auth_client.post('/assessments/create', data={
        'name': 'API Gateway Security Audit',
        'target_url': 'https://api.test-target.local',
        'scope_notes': 'Strictly /v1 endpoints',
        'tester': 'Security Engineer',
        'status': 'Planned'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'API Gateway Security Audit' in res.data

    with app.app_context():
        assessment = Assessment.query.filter_by(name='API Gateway Security Audit').first()
        assert assessment is not None
        a_id = assessment.id

    # 2. View Detail
    res_detail = auth_client.get(f'/assessments/{a_id}')
    assert res_detail.status_code == 200
    assert b'https://api.test-target.local' in res_detail.data

    # 3. Edit Assessment
    res_edit = auth_client.post(f'/assessments/{a_id}/edit', data={
        'name': 'API Gateway Security Audit (Updated)',
        'target_url': 'https://api.test-target.local',
        'tester': 'Security Lead',
        'status': 'In Progress'
    }, follow_redirects=True)
    assert res_edit.status_code == 200
    assert b'API Gateway Security Audit (Updated)' in res_edit.data

    # 4. Delete Assessment
    res_del = auth_client.post(f'/assessments/{a_id}/delete', follow_redirects=True)
    assert res_del.status_code == 200

    with app.app_context():
        assert Assessment.query.get(a_id) is None
