"""
Unit tests for Authentication and Protected Routes.
"""

from models import User


def test_password_hashing(app):
    """Verify Werkzeug password hashing."""
    with app.app_context():
        user = User(username='secuser', email='sec@vulntrack.local')
        user.set_password('SecretP@ssword123')
        assert user.password_hash != 'SecretP@ssword123'
        assert user.check_password('SecretP@ssword123') is True
        assert user.check_password('WrongPassword') is False


def test_protected_routes_redirect_unauthenticated(client):
    """Verify unauthorized users are redirected to login."""
    res = client.get('/', follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.headers['Location']

    res_ass = client.get('/assessments/', follow_redirects=False)
    assert res_ass.status_code == 302

    res_vuln = client.get('/vulnerabilities/', follow_redirects=False)
    assert res_vuln.status_code == 302


def test_successful_login_and_logout(client):
    """Verify user login and logout lifecycle."""
    # Login
    res = client.post('/login', data={
        'username': 'testadmin',
        'password': 'TestAdmin123!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'VAPT Security Dashboard' in res.data

    # Logout
    res_logout = client.get('/logout', follow_redirects=True)
    assert res_logout.status_code == 200
    assert b'Sign In to Platform' in res_logout.data


def test_failed_login(client):
    """Verify rejection of bad credentials."""
    res = client.post('/login', data={
        'username': 'testadmin',
        'password': 'BadPassword!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Invalid username or password' in res.data
