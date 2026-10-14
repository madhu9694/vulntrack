"""
VulnTrack Authentication Blueprint.

Handles secure login, logout, and user session lifecycle.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from forms import LoginForm
from services.audit_service import log_action

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            log_action('LOGIN', f"User {user.username} successfully authenticated.", target_id=user.id)
            flash(f"Welcome back, {user.username}!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            log_action('LOGIN_FAILED', f"Failed login attempt for username: {form.username.data.strip()}")
            flash("Invalid username or password. Please try again.", "danger")

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    uid = current_user.id
    logout_user()
    log_action('LOGOUT', f"User {username} logged out.", target_id=uid, user_override=username)
    flash("You have been logged out safely.", "info")
    return redirect(url_for('auth.login'))
