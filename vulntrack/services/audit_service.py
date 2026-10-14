"""
VulnTrack Audit Logging Service.

Provides centralized recording of administrative and security actions
to maintain auditability for compliance and assessment verification.
"""

from flask import request
from flask_login import current_user
from extensions import db
from models import AuditLog


def log_action(
    action_type: str,
    details: str,
    target_id: str = None,
    user_override: str = None
) -> None:
    """
    Safely append an event to the audit log.
    Captures user identity, IP address, and timestamp automatically.
    """
    try:
        user_id = None
        username = user_override or 'Anonymous / System'

        if current_user and current_user.is_authenticated:
            user_id = current_user.id
            username = current_user.username

        # Get client IP safely
        ip = "127.0.0.1"
        if request:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr or "127.0.0.1").split(',')[0].strip()

        entry = AuditLog(
            user_id=user_id,
            username=username,
            action_type=action_type,
            target_id=str(target_id) if target_id is not None else None,
            details=details,
            ip_address=ip
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        # Prevent audit log failures from breaking the primary user action
        db.session.rollback()
        # In development, print failure safely
        print(f"[AUDIT LOG ERROR] Failed to write audit event: {e}")
