"""Authentication routes and decorators."""

import re
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

from extensions import limiter
from utils.db import get_db

auth_bp = Blueprint("auth", __name__)


# ---------------------------
# Authentication Decorators
# ---------------------------
def admin_required(view):
    """Decorator to require admin login."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if "admin_username" not in session:
            return redirect(url_for("auth.admin_login"))
        db = get_db()
        cur = db.execute(
            "SELECT * FROM admins WHERE username = ?", (session["admin_username"],)
        )
        if cur.fetchone() is None:
            return redirect(url_for("auth.admin_login"))
        return view(**kwargs)
    return wrapped_view


def login_required(view):
    """Decorator to require user login."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if "netid" not in session:
            return redirect(url_for("auth.login"))
        # Validate user still exists in database (except for guest)
        netid = session.get("netid")
        if netid and netid != "guest":
            try:
                db = get_db()
                cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
                if cur.fetchone() is None:
                    session.clear()
                    flash("Your account no longer exists. Please contact the administrator.", "danger")
                    return redirect(url_for("auth.login"))
            except Exception as e:
                logging.error(f"Error validating user session: {e}")
                # Allow request to proceed if DB check fails to avoid blocking legitimate users
        return view(**kwargs)
    return wrapped_view


def validate_session():
    """Validate session timeout and security. Returns tuple (valid, redirect_url)."""
    if session.get("admin_username"):
        login_time_str = session.get("admin_login_time")
        if login_time_str:
            try:
                login_time = datetime.fromisoformat(login_time_str)
                if datetime.now() - login_time > timedelta(hours=8):
                    admin_user = session.get("admin_username", "unknown")
                    logging.info(f"Security: Admin '{admin_user}' session expired")
                    session.clear()
                    flash("Session expired. Please log in again.", "danger")
                    return (False, "auth.admin_login")
            except (ValueError, TypeError):
                session.clear()
                flash("Invalid session. Please log in again.", "danger")
                return (False, "auth.admin_login")

    if session.get("netid"):
        login_time_str = session.get("user_login_time")
        if login_time_str:
            try:
                login_time = datetime.fromisoformat(login_time_str)
                if datetime.now() - login_time > timedelta(hours=8):
                    session.clear()
                    flash("Session expired. Please log in again.", "danger")
                    return (False, "auth.login")
            except (ValueError, TypeError):
                session.clear()
                flash("Invalid session. Please log in again.", "danger")
                return (False, "auth.login")

    return (True, None)


# ---------------------------
# User Authentication Routes
# ---------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        netid = request.form.get("netid", "").strip().lower()

        # Input validation
        if not netid:
            flash("NetID is required.", "danger")
            return render_template("login.html")

        if len(netid) > 20 or not re.match(r"^[a-zA-Z0-9_-]+$", netid):
            flash("Invalid NetID format.", "danger")
            return render_template("login.html")

        try:
            db = get_db()
            cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
            user = cur.fetchone()
            if user:
                # Regenerate session to prevent session fixation
                session.clear()
                session["netid"] = netid
                session["user_login_time"] = datetime.now().isoformat()
                logging.info(
                    f"Security: User '{netid}' logged in successfully from {get_remote_address()}"
                )
                flash("Logged in successfully.", "success")
                return redirect(url_for("main.index"))
            else:
                logging.warning(
                    f"Security: Failed login attempt for netid '{netid}' from {get_remote_address()}"
                )
                flash("Invalid credentials. Please contact the administrator.", "danger")
        except Exception as e:
            logging.error(f"User login error: {e}")
            flash("An error occurred during login. Please try again.", "danger")

    return render_template("login.html")


@auth_bp.route("/guest_login", methods=["POST"])
@limiter.limit("10 per minute")
def guest_login():
    # Regenerate session to prevent session fixation
    session.clear()
    session["netid"] = "guest"
    session["user_login_time"] = datetime.now().isoformat()
    logging.info(f"Security: Guest login from {get_remote_address()}")
    flash("Logged in as guest.", "info")
    return redirect(url_for("main.index"))


@auth_bp.route("/logout")
@login_required
@limiter.limit("10 per minute")
def logout():
    user_netid = session.get("netid", "unknown")
    session.clear()
    logging.info(f"Security: User '{user_netid}' logged out")
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------
# Admin Authentication Routes
# ---------------------------
@auth_bp.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Input validation
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("admin_login.html")

        if len(username) > 50 or len(password) > 100:
            flash("Invalid input length.", "danger")
            return render_template("admin_login.html")

        try:
            db = get_db()
            cur = db.execute("SELECT * FROM admins WHERE username = ?", (username,))
            admin = cur.fetchone()
            if admin and check_password_hash(admin["password"], password):
                # Regenerate session to prevent session fixation
                session.clear()
                session["admin_username"] = username
                session["admin_login_time"] = datetime.now().isoformat()
                logging.info(
                    f"Security: Admin '{username}' logged in successfully from {get_remote_address()}"
                )
                flash("Admin logged in successfully.", "success")
                return redirect(url_for("admin.admin_dashboard"))
            else:
                # Use generic error message to prevent username enumeration
                logging.warning(
                    f"Security: Failed admin login attempt for username '{username}' from {get_remote_address()}"
                )
                flash("Invalid credentials.", "danger")
        except Exception as e:
            logging.error(f"Admin login error: {e}")
            flash("An error occurred during login. Please try again.", "danger")

    return render_template("admin_login.html")


@auth_bp.route("/admin/logout")
@admin_required
@limiter.limit("10 per minute")
def admin_logout():
    admin_user = session.get("admin_username", "unknown")
    session.clear()
    logging.info(f"Security: Admin '{admin_user}' logged out")
    flash("Admin logged out.", "info")
    return redirect(url_for("auth.admin_login"))
