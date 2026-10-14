"""
VulnTrack Pytest Fixtures and Test Setup.
"""

import pytest
from app import create_app
from extensions import db
from models import User, Assessment, VulnerabilityFinding


@pytest.fixture
def app():
    """Create Flask application instance configured for testing."""
    application = create_app('testing')
    
    with application.app_context():
        db.create_all()
        # Create default test user
        user = User(username='testadmin', email='testadmin@vulntrack.local', role='Admin')
        user.set_password('TestAdmin123!')
        db.session.add(user)
        db.session.commit()

        yield application

        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Test client authenticated as admin."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'TestAdmin123!'
    }, follow_redirects=True)
    return client


@pytest.fixture
def sample_assessment(app):
    """Sample assessment for testing."""
    with app.app_context():
        assessment = Assessment(
            name="Unit Test Assessment",
            target_url="https://test.target.local",
            scope_notes="Test scope",
            tester="QA Engineer",
            status="In Progress"
        )
        db.session.add(assessment)
        db.session.commit()
        return assessment.id
