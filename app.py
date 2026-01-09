"""Charter Meals - Flask web application for meal sign-ups."""

import os
import re
import logging
from datetime import datetime

from flask import Flask, redirect, url_for, flash, session, request, jsonify
from flask_limiter.util import get_remote_address

from config import Config, CSP
from extensions import init_extensions, csrf
from utils.db import get_db, close_db, init_db, parse_schema, get_create_statements
from routes import register_blueprints
from routes.auth import validate_session

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Ensure database directory exists
db_dir = os.path.dirname(app.config["DATABASE"])
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, mode=0o755)
    except OSError as e:
        logging.error(f"Failed to create database directory {db_dir}: {e}")
        raise RuntimeError(f"Cannot create database directory: {e}")

# Initialize extensions
init_extensions(app, CSP)

# Register database teardown
app.teardown_appcontext(close_db)

# Register blueprints
register_blueprints(app)


# ---------------------------
# CLI Commands
# ---------------------------
@app.cli.command("init-db")
def init_db_command():
    """Clear existing data, create new tables, and default admin account."""
    with app.app_context():
        init_db()
    print(
        "Initialized the database with default admin (username: admin, password: admin)."
    )


@app.cli.command("migrate-db")
def migrate_db_command():
    """Migrate the database schema to match schema.sql without losing data."""
    ALLOWED_TABLES = {
        "users",
        "meal_slots",
        "reservations",
        "admins",
        "settings",
        "website_content",
        "archived_users",
        "archived_meal_slots",
        "archived_reservations",
    }
    COLUMN_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

    db = get_db()
    cur = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {row["name"] for row in cur.fetchall()}
    create_stmts = get_create_statements()
    parsed_schema = parse_schema()
    for table, create_stmt in create_stmts.items():
        if table not in ALLOWED_TABLES:
            print(f"Skipping unknown table '{table}' (not in whitelist).")
            continue
        if table not in existing_tables:
            db.execute(create_stmt)
            print(f"Created missing table '{table}'.")
        else:
            cur = db.execute(f"PRAGMA table_info({table})")
            existing_columns = {row["name"] for row in cur.fetchall()}
            for col, col_def in parsed_schema.get(table, []):
                if not COLUMN_NAME_PATTERN.match(col):
                    print(f"Skipping invalid column name '{col}' in table '{table}'.")
                    continue
                if col not in existing_columns:
                    try:
                        db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                        print(f"Added missing column '{col}' to table '{table}'.")
                    except Exception as e:
                        print(f"Could not add column '{col}' to table '{table}': {e}")
    db.commit()
    print("Database migration complete.")


# ---------------------------
# Template Filters
# ---------------------------
@app.template_filter("weekday")
def weekday_filter(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return d.weekday()
    except (ValueError, TypeError):
        return 0


@app.template_filter("dayname")
def dayname_filter(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return d.strftime("%A")
    except (ValueError, TypeError):
        return "Unknown"


@app.template_filter("meal_time")
def meal_time_filter(meal_type, date_str):
    """Return the meal time range for a given meal type and date."""
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        weekday = d.weekday()
        meal_type_lower = (meal_type or "").lower()
        if weekday < 5:  # Weekday
            if meal_type_lower == "breakfast":
                return "8-10"
            elif meal_type_lower == "lunch":
                return "11:30-1:30"
            elif meal_type_lower == "dinner":
                return "5:30-7:30"
        else:  # Weekend
            if meal_type_lower == "brunch":
                return "11-1:30"
            elif meal_type_lower == "dinner":
                return "5:30-7"
        return ""
    except (ValueError, TypeError):
        return ""


@app.template_filter("display_date")
def display_date_filter(date_str):
    """Return the date in the format: 'DayName, Mon DD' (no year)."""
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return d.strftime("%A, %b %d")
    except (ValueError, TypeError):
        return "Unknown Date"


@app.template_filter("safe_url")
def safe_url_filter(url):
    """Validate and return URL only if it's safe (http/https/mailto), otherwise return empty string."""
    if not url:
        return ""
    url = str(url).strip()
    # Only allow http, https, and mailto URLs
    if url.startswith(("http://", "https://", "mailto:")):
        return url
    return ""


# ---------------------------
# Before Request Handler
# ---------------------------
@app.before_request
def before_request_handler():
    # Skip session validation for auth routes and static files to prevent redirect loops
    skip_endpoints = {
        "auth.login",
        "auth.admin_login",
        "auth.guest_login",
        "auth.logout",
        "auth.admin_logout",
        "static",
        "health_check",
    }
    if request.endpoint in skip_endpoints:
        return None

    # Validate session for all other routes
    valid, redirect_endpoint = validate_session()
    if not valid and redirect_endpoint:
        return redirect(url_for(redirect_endpoint))

    # If the request path starts with /admin and the endpoint is not "auth.admin_login",
    # ensure an admin is logged in.
    if request.path.startswith("/admin") and request.endpoint != "auth.admin_login":
        if "admin_username" not in session:
            return redirect(url_for("auth.admin_login"))


# ---------------------------
# Error Handlers
# ---------------------------
@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for("auth.admin_login"))


@app.errorhandler(403)
def forbidden(error):
    flash("Access forbidden.", "danger")
    return redirect(url_for("auth.login"))


@app.errorhandler(404)
def not_found(error):
    flash("Page not found.", "danger")
    return redirect(url_for("main.index"))


@app.errorhandler(429)
def ratelimit_handler(error):
    logging.warning(f"Rate limit exceeded from {get_remote_address()}")
    flash("Too many requests. Please try again later.", "danger")
    return redirect(url_for("auth.login"))


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {error}")
    try:
        session.clear()
    except Exception:
        pass
    flash("An internal server error occurred. Please try again later.", "danger")
    return redirect(url_for("auth.login"))


# ---------------------------
# Health Check
# ---------------------------
from extensions import limiter, cache


@app.route("/health")
@limiter.limit("60 per minute")
@csrf.exempt
def health_check():
    """Health check endpoint for monitoring."""
    try:
        db = get_db()
        db.execute("SELECT 1")

        try:
            cache.set("health_check", "ok", timeout=10)
            cache_status = "ok"
        except Exception:
            cache_status = "error"

        try:
            version_path = os.path.join(os.path.dirname(__file__), "VERSION")
            with open(version_path, "r") as vf:
                version = vf.read().strip()
        except Exception:
            version = "unknown"

        return jsonify(
            {
                "status": "healthy",
                "version": version,
                "database": "ok",
                "cache": cache_status,
                "timestamp": datetime.now().isoformat(),
            }
        )
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        try:
            version_path = os.path.join(os.path.dirname(__file__), "VERSION")
            with open(version_path, "r") as vf:
                version = vf.read().strip()
        except Exception:
            version = "unknown"
        return (
            jsonify(
                {
                    "status": "unhealthy",
                    "version": version,
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            500,
        )


# ---------------------------
# Context Processors
# ---------------------------
@app.context_processor
def inject_version():
    try:
        version_path = os.path.join(os.path.dirname(__file__), "VERSION")
        with open(version_path, "r") as vf:
            version = vf.read().strip()
    except Exception:
        version = "unknown"
    return {"version": version}


@app.context_processor
def inject_asset_version():
    """Inject a version number for static assets to improve cache control."""

    def asset_url_for(filename):
        import time

        try:
            version_path = os.path.join(os.path.dirname(__file__), "VERSION")
            with open(version_path, "r") as vf:
                version = vf.read().strip().replace(".", "_")
        except Exception:
            version = str(int(time.time()))

        return url_for("static", filename=filename) + "?v=" + version

    return dict(asset_url_for=asset_url_for)


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    app.run(debug=debug_mode)
