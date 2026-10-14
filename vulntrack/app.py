"""
VulnTrack — VAPT Vulnerability Management and Risk Prioritization System
Main Application Factory and CLI management commands.
"""

import os
from datetime import datetime
from flask import Flask, render_template
import click

from config import config_by_name
from extensions import db, login_manager, csrf
from models import User, Assessment, VulnerabilityFinding, AuditLog


def create_app(config_name=None):
    """Flask application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(__name__)
    app.config.from_object(config_by_name.get(config_name, config_by_name['default']))

    # Ensure instance folder exists for SQLite
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.assessments import assessments_bp
    from routes.vulnerabilities import vulnerabilities_bp
    from routes.remediation import remediation_bp
    from routes.comparison import comparison_bp
    from routes.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(remediation_bp)
    app.register_blueprint(comparison_bp)
    app.register_blueprint(reports_bp)

    # Global Jinja Context & Filters
    @app.context_processor
    def inject_global_data():
        return {
            'now': datetime.utcnow(),
            'app_name': 'VulnTrack'
        }

    @app.template_filter('format_date')
    def format_date_filter(val):
        if not val:
            return '—'
        if isinstance(val, str):
            try:
                val = datetime.fromisoformat(val)
            except Exception:
                return val
        return val.strftime('%b %d, %Y')

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return render_template('errors/413.html'), 413

    # Register custom CLI commands
    register_cli_commands(app)

    return app


def register_cli_commands(app):
    """Attach Click commands to manage the database and demonstration data."""

    @app.cli.command("init-db")
    def init_db():
        """Create database tables."""
        db.create_all()
        click.echo("[OK] Initialized SQLite database successfully.")

    @app.cli.command("create-admin")
    @click.option("--username", default="admin", help="Admin username")
    @click.option("--email", default="admin@vulntrack.local", help="Admin email")
    @click.option("--password", default="Admin@VulnTrack2026!", help="Admin password")
    def create_admin(username, email, password):
        """Create initial local administrator account."""
        db.create_all()
        existing = User.query.filter_by(username=username).first()
        if existing:
            click.echo(f"[!] User '{username}' already exists.")
            return

        user = User(username=username, email=email, role="Admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"[OK] Administrator account '{username}' created successfully.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Seed rich synthetic demo data for viva and evaluation."""
        from init_demo import populate_demo_data
        populate_demo_data()
        click.echo("[OK] Demonstration data seeded successfully.")


if __name__ == '__main__':
    application = create_app()
    application.run(host='127.0.0.1', port=5000, debug=True)
