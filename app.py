import os
import re
import sqlite3
import logging
import csv, io
from datetime import datetime, date, timedelta
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    g,
    abort,
    Response,
)
from werkzeug.security import generate_password_hash, check_password_hash

# --- Security Extensions ---
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Performance Extensions ---
from flask_compress import Compress
from flask_caching import Cache

# For US Eastern time handling
from zoneinfo import ZoneInfo

app = Flask(__name__)

# Load secret key from secrets.txt
secret_path = os.path.join(os.path.dirname(__file__), "secrets.txt")
try:
    with open(secret_path, "r") as f:
        app.secret_key = f.read().strip()
        if not app.secret_key or len(app.secret_key or "") < 32:
            raise RuntimeError("Secret key must be at least 32 characters long")
except FileNotFoundError:
    raise RuntimeError(
        "Secret key file not found. Please create a 'secrets.txt' file with a generated secret key."
    )
except Exception as e:
    raise RuntimeError(f"Error reading secret key: {str(e)}")

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # 8 hour session timeout
)

logging.basicConfig(level=logging.INFO)

last_slot_generation = None

# New Content Security Policy as required.
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://code.jquery.com", "'unsafe-inline'"],
    "style-src": ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
)

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute"],
    storage_uri="redis://localhost:6379/0",
)
limiter.init_app(app)

# Use local database for development, production path for deployment
if os.path.exists("/var/www/data"):
    app.config["DATABASE"] = "/var/www/data/meals.db"
else:
    app.config["DATABASE"] = "meals.db"

# Ensure database directory exists
db_dir = os.path.dirname(app.config["DATABASE"])
if db_dir and not os.path.exists(db_dir):
    try:
        os.makedirs(db_dir, mode=0o755)
    except OSError as e:
        logging.error(f"Failed to create database directory {db_dir}: {e}")
        raise RuntimeError(f"Cannot create database directory: {e}")

Compress(app)

cache_config = {
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 300,
    "CACHE_THRESHOLD": 500,  # Store up to 500 items in cache
}
cache = Cache(app, config=cache_config)


# ---------------------------
# Database Helpers
# ---------------------------
def get_db():
    if "db" not in g:
        try:
            g.db = sqlite3.connect(app.config["DATABASE"], check_same_thread=False)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON;")
            g.db.execute("PRAGMA journal_mode=WAL;")
            g.db.execute("PRAGMA synchronous=NORMAL;")
            g.db.execute("PRAGMA cache_size=10000;")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            raise RuntimeError(f"Database connection failed: {e}")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    with app.open_resource("schema.sql", mode="r") as f:
        db.executescript(f.read())
    # Create default admin account
    db.execute(
        "INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)",
        ("admin", generate_password_hash("admin", method="pbkdf2:sha256")),
    )
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    """Clear existing data, create new tables, and default admin account."""
    init_db()
    print(
        "Initialized the database with default admin (username: admin, password: admin)."
    )


# --- Dynamic Migration Command (with inline comment stripping) ---
def parse_schema():
    schema = {}
    with open("schema.sql", "r") as f:
        content = f.read()
    import re

    pattern = re.compile(
        r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\);", re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)
    for table, cols in matches:
        col_defs = []
        # Split by comma and remove inline comments (anything after '--')
        for line in cols.split(","):
            line = line.split("--")[0].strip()
            if not line:
                continue
            if (
                line.upper().startswith("UNIQUE")
                or line.upper().startswith("FOREIGN")
                or line.upper().startswith("CONSTRAINT")
            ):
                continue
            m = re.match(r"(\w+)\s+(.+)", line)
            if m:
                col_name = m.group(1)
                col_def = m.group(2).strip()
                col_defs.append((col_name, col_def))
        schema[table] = col_defs
    return schema


def get_create_statements():
    create_stmts = {}
    with open("schema.sql", "r") as f:
        content = f.read()
    import re

    pattern = re.compile(
        r"(CREATE TABLE IF NOT EXISTS (\w+)\s*\(.*?\);)", re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)
    for full_stmt, table in matches:
        create_stmts[table] = full_stmt
    return create_stmts


@app.cli.command("migrate-db")
def migrate_db_command():
    """Migrate the database schema to match schema.sql without losing data."""
    db = get_db()
    cur = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = {row["name"] for row in cur.fetchall()}
    create_stmts = get_create_statements()
    parsed_schema = parse_schema()
    for table, create_stmt in create_stmts.items():
        if table not in existing_tables:
            db.execute(create_stmt)
            print(f"Created missing table '{table}'.")
        else:
            cur = db.execute(f"PRAGMA table_info({table})")
            existing_columns = {row["name"] for row in cur.fetchall()}
            for col, col_def in parsed_schema.get(table, []):
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
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    return d.weekday()


@app.template_filter("dayname")
def dayname_filter(date_str):
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    return d.strftime("%A")


@app.template_filter("meal_time")
def meal_time_filter(meal_type, date_str):
    """Return the meal time range for a given meal type and date.
    For Monday–Friday:
      - Breakfast: 8-10
      - Lunch: 11:30-1:30
      - Dinner: 5:30-7:30
    For Weekend:
      - Brunch: 11-1:30
      - Dinner: 5:30-7
    """
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    weekday = d.weekday()  # Monday=0 ... Sunday=6
    meal_type_lower = meal_type.lower()
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


@app.template_filter("display_date")
def display_date_filter(date_str):
    """Return the date in the format: 'DayName, Mon DD' (no year)."""
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    return d.strftime("%A, %b %d")


# ---------------------------
# Helper Functions for Signup Time
# ---------------------------
def next_occurrence(target_weekday, target_time, ref):
    diff = (target_weekday - ref.weekday()) % 7
    candidate = ref.replace(
        hour=target_time.hour, minute=target_time.minute, second=0, microsecond=0
    ) + timedelta(days=diff)
    if candidate < ref:
        candidate += timedelta(days=7)
    return candidate


# ---------------------------
# Application Helpers
# ---------------------------
def generate_next_week_meal_slots():
    global last_slot_generation
    try:
        if (
            last_slot_generation
            and (datetime.now() - last_slot_generation).total_seconds() < 21600
        ):
            return
        
        last_slot_generation = datetime.now()
        db = get_db()
        today = date.today()
        next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
        days = [next_monday + timedelta(days=i) for i in range(7)]
        
        slots_created = 0
        for d in days:
            day_str = d.isoformat()
            meals = (
                ["breakfast", "lunch", "dinner"]
                if d.weekday() < 5
                else ["brunch", "dinner"]
            )
            for meal in meals:
                try:
                    cur = db.execute(
                        "SELECT id FROM meal_slots WHERE date = ? AND meal_type = ?",
                        (day_str, meal),
                    )
                    if cur.fetchone() is None:
                        db.execute(
                            "INSERT INTO meal_slots (date, meal_type, capacity) VALUES (?, ?, ?)",
                            (day_str, meal, 25),
                        )
                        slots_created += 1
                except Exception as e:
                    logging.error(f"Error creating meal slot for {day_str} {meal}: {e}")
        
        try:
            db.commit()
            if slots_created > 0:
                logging.info(f"Generated {slots_created} new meal slots for week starting {next_monday}")
        except Exception as e:
            logging.error(f"Error committing meal slot generation: {e}")
            db.rollback()
            
    except Exception as e:
        logging.error(f"Error in generate_next_week_meal_slots: {e}")
        # Don't raise the exception - we want the app to continue working


def is_pub_slot(meal_slot):
    slot_date = datetime.strptime(meal_slot["date"], "%Y-%m-%d").date()
    return meal_slot["meal_type"].lower() == "dinner" and slot_date.weekday() in [1, 3]


# ---------------------------
# Updated Decorators
# ---------------------------
def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "admin_username" not in session:
            return redirect(url_for("admin_login"))
        db = get_db()
        cur = db.execute(
            "SELECT * FROM admins WHERE username = ?", (session["admin_username"],)
        )
        if cur.fetchone() is None:
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "netid" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


# ---------------------------
# Enforce Admin Login on All Admin Routes
# ---------------------------
def validate_session():
    """Validate session timeout and security."""
    if session.get("admin_username"):
        login_time_str = session.get("admin_login_time")
        if login_time_str:
            try:
                login_time = datetime.fromisoformat(login_time_str)
                if datetime.now() - login_time > timedelta(hours=8):
                    session.clear()
                    flash("Session expired. Please log in again.", "danger")
                    return False
            except (ValueError, TypeError):
                session.clear()
                flash("Invalid session. Please log in again.", "danger")
                return False
    
    if session.get("netid"):
        login_time_str = session.get("user_login_time")
        if login_time_str:
            try:
                login_time = datetime.fromisoformat(login_time_str)
                if datetime.now() - login_time > timedelta(hours=8):
                    session.clear()
                    flash("Session expired. Please log in again.", "danger")
                    return False
            except (ValueError, TypeError):
                session.clear()
                flash("Invalid session. Please log in again.", "danger")
                return False
    
    return True

@app.before_request
def require_admin_for_admin_routes():
    # Validate session first
    if not validate_session():
        return redirect(url_for("login"))
    
    # If the request path starts with /admin and the endpoint is not "admin_login",
    # ensure an admin is logged in.
    if request.path.startswith("/admin") and request.endpoint != "admin_login":
        if "admin_username" not in session:
            return redirect(url_for("admin_login"))


# ---------------------------
# Admin Authentication Routes
# ---------------------------
@app.route("/admin/login", methods=["GET", "POST"])
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
                session["admin_username"] = username
                session["admin_login_time"] = datetime.now().isoformat()
                flash("Admin logged in successfully.", "success")
                return redirect(url_for("admin"))
            else:
                flash("Invalid admin credentials.", "danger")
        except Exception as e:
            logging.error(f"Admin login error: {e}")
            flash("An error occurred during login. Please try again.", "danger")
    
    return render_template("admin_login.html")


@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.pop("admin_username", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/change_password", methods=["GET", "POST"])
@admin_required
def admin_change_password():
    if request.method == "POST":
        current = request.form["current_password"].strip()
        new_pass = request.form["new_password"].strip()
        confirm = request.form["confirm_password"].strip()
        if new_pass != confirm:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("admin_change_password"))
        db = get_db()
        cur = db.execute(
            "SELECT * FROM admins WHERE username = ?", (session["admin_username"],)
        )
        admin = cur.fetchone()
        if admin and check_password_hash(admin["password"], current):
            new_hash = generate_password_hash(new_pass, method="pbkdf2:sha256")
            db.execute(
                "UPDATE admins SET password = ? WHERE username = ?",
                (new_hash, session["admin_username"]),
            )
            db.commit()
            flash("Password updated successfully.", "success")
            return redirect(url_for("admin"))
        else:
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("admin_change_password"))
    return render_template("admin_change_password.html")


@app.route("/admin/add_admin", methods=["POST"])
def admin_add_admin():
    # Allow any logged-in user to add admins
    if not session.get("netid") and not session.get("admin_username"):
        flash("You must be logged in to add admin accounts.", "danger")
        return redirect(url_for("admin"))
    
    username = request.form.get("new_admin_username", "").strip()
    password = request.form.get("new_admin_password", "").strip()
    if not username or not password:
        flash("Username and password are required for new admin.", "danger")
        return redirect(url_for("admin"))
    db = get_db()
    try:
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        db.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        flash(f"Admin account '{username}' created successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Admin account already exists.", "warning")
    return redirect(url_for("admin"))


@app.route("/admin/delete_admin/<username>", methods=["POST"])
@admin_required
def admin_delete_admin(username):
    if session.get("admin_username") != "admin":
        flash("You do not have permission to delete admin accounts.", "danger")
        return redirect(url_for("admin"))
    if username == "admin":
        flash("Cannot delete the primary admin account.", "danger")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute("DELETE FROM admins WHERE username = ?", (username,))
    db.commit()
    flash(f"Admin account '{username}' deleted.", "success")
    return redirect(url_for("admin"))


# ---------------------------
# Export Functionality
# ---------------------------
def export_sort_key(row):
    # Compute weekday (Monday=0, Sunday=6)
    dt = datetime.strptime(row["date"], "%Y-%m-%d").date()
    weekday = dt.weekday()
    # Define meal order mapping; treat 'brunch' as breakfast (order 1)
    meal = row["meal_type"].lower()
    meal_order = {"breakfast": 1, "lunch": 2, "dinner": 3, "brunch": 1}.get(meal, 99)
    # Extract first name from the user's name
    first_name = (row["name"] or "").split()[0].lower() if row["name"] else ""
    return (weekday, meal_order, first_name)


@app.route("/admin/download_meal_signups/<week_start>")
@admin_required
def admin_download_meal_signups_week(week_start):
    db = get_db()
    week_start_date = datetime.strptime(week_start, "%Y-%m-%d").date()
    week_end_date = week_start_date + timedelta(days=6)
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type, u.name, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        LEFT JOIN users u ON r.netid = u.netid
        WHERE ms.date BETWEEN ? AND ?
        """,
        (week_start_date.isoformat(), week_end_date.isoformat()),
    )
    rows = cur.fetchall()
    sorted_rows = sorted(rows, key=export_sort_key)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "name"])
    for row in sorted_rows:
        name = row["name"] or "No Name"
        writer.writerow([row["date"], row["meal_type"], name])
    csv_content = output.getvalue()
    output.close()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-disposition": "attachment; filename=meal_signups_"
            + week_start
            + ".csv"
        },
    )


@app.route("/admin/download_all_meal_signups")
@admin_required
def admin_download_all_meal_signups():
    db = get_db()
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type, u.name, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        LEFT JOIN users u ON r.netid = u.netid
        """
    )
    rows = cur.fetchall()
    sorted_rows = sorted(rows, key=export_sort_key)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "name"])
    for row in sorted_rows:
        name = row["name"] or "No Name"
        writer.writerow([row["date"], row["meal_type"], name])
    csv_content = output.getvalue()
    output.close()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=meal_signups_all.csv"},
    )


# ---------------------------
# Admin Dashboard and Settings
# ---------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    # Allow any logged-in user to access admin page (for adding admins)
    if not session.get("netid") and not session.get("admin_username"):
        flash("You must be logged in to access the admin page.", "danger")
        return redirect(url_for("login"))
    db = get_db()
    
    # Handle POST requests for content management
    if request.method == "POST":
        updated_count = 0
        content_keys = [
            'welcome_header', 'welcome_message', 'contact_info', 
            'meal_rules_title', 'meal_rules', 'feedback_link', 'feedback_text'
        ]
        for key in content_keys:
            if key == 'meal_rules':
                # Try to get the list of rules from the form
                rules_list = request.form.getlist('content_value_meal_rules_list[]')
                if rules_list:
                    # Remove empty rules and strip whitespace
                    rules_list = [r.strip() for r in rules_list if r.strip()]
                    content_value = '\n'.join(rules_list)
                else:
                    # Fallback to textarea
                    content_value = request.form.get(f"content_value_{key}", "").strip()
            else:
                content_value = request.form.get(f"content_value_{key}", "").strip()
            if content_value:
                try:
                    html_content = parse_markdown(content_value, key)
                    db.execute(
                        "INSERT OR REPLACE INTO website_content (content_key, content_value, last_updated) VALUES (?, ?, CURRENT_TIMESTAMP)",
                        (key, html_content)
                    )
                    updated_count += 1
                except Exception as e:
                    flash(f"Error updating {key}: {str(e)}", "danger")
        if updated_count > 0:
            db.commit()
            flash(f"Successfully updated {updated_count} content items.", "success")
        else:
            flash("No content was updated.", "warning")
        return redirect(url_for("admin"))

    # --- New: Fetch users and attach their reservations for current & next week ---
    cur = db.execute("SELECT netid, name FROM users ORDER BY netid")
    users_rows = cur.fetchall()

    today = date.today()
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=6)
    next_monday = current_week_start + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)

    # Get reservations for current week and next week:
    week_range_start = current_week_start.isoformat()
    week_range_end = next_sunday.isoformat()

    cur = db.execute(
        """
        SELECT r.netid, ms.date, ms.meal_type
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE ms.date BETWEEN ? AND ?
        ORDER BY ms.date, ms.meal_type
        """,
        (week_range_start, week_range_end),
    )
    all_reservations = cur.fetchall()

    reservations_by_user = {}
    for res in all_reservations:
        reservations_by_user.setdefault(res["netid"], []).append(res)

    users = []
    for row in users_rows:
        user = dict(row)
        user["reservations"] = reservations_by_user.get(user["netid"], [])
        users.append(user)
    # --- End new user reservations block ---

    # Existing queries for reservations_by_slot for the reservations subtabs:
    cur = db.execute(
        """
        SELECT r.id as reservation_id, r.netid, u.name, ms.id as meal_slot_id, ms.date, ms.meal_type, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        LEFT JOIN users u ON r.netid = u.netid
        ORDER BY ms.date, ms.meal_type
        """
    )
    reservations = cur.fetchall()
    reservations_by_slot = {}
    for res in reservations:
        key = f"{res['date']} - {res['meal_type']}"
        if key not in reservations_by_slot:
            reservations_by_slot[key] = {"reservations": []}
        reservations_by_slot[key]["reservations"].append(res)
    cur = db.execute("SELECT DISTINCT date FROM meal_slots ORDER BY date DESC")
    week_list = sorted(
        {
            datetime.strptime(row["date"], "%Y-%m-%d").date()
            - timedelta(
                days=datetime.strptime(row["date"], "%Y-%m-%d").date().weekday()
            )
            for row in cur.fetchall()
        },
        reverse=True,
    )
    cur = db.execute("SELECT username FROM admins ORDER BY username")
    admin_accounts = [row["username"] for row in cur.fetchall()]
    is_super_admin = session.get("admin_username") == "admin"
    is_admin = session.get("admin_username") is not None

    # For Reservations subtabs: next week's meal slots grouped by weekday (0=Monday ... 6=Sunday)
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    cur = db.execute(
        "SELECT * FROM meal_slots WHERE date BETWEEN ? AND ? ORDER BY date",
        (next_monday.isoformat(), next_sunday.isoformat()),
    )
    week_meal_slots = cur.fetchall()
    weekly_slots = {i: [] for i in range(7)}
    for slot in week_meal_slots:
        d = datetime.strptime(slot["date"], "%Y-%m-%d").date()
        weekly_slots[d.weekday()].append(slot)
    # --- Sort each day's slots by meal order ---
    for weekday, slots in weekly_slots.items():
        if slots:
            d = datetime.strptime(slots[0]["date"], "%Y-%m-%d").date()
            if d.weekday() < 5:
                order = {"breakfast": 1, "lunch": 2, "dinner": 3}
            else:
                order = {"brunch": 1, "dinner": 2}
            slots.sort(key=lambda s: order.get(s["meal_type"].lower(), 99))

    # Get reservation settings
    cur = db.execute(
        "SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)",
        (
            "reservation_status",
            "reservation_open_day",
            "reservation_open_time",
            "reservation_close_day",
            "reservation_close_time",
        ),
    )
    new_settings = {row["key"]: row["value"] for row in cur.fetchall()}
    reservation_status = new_settings.get("reservation_status", "auto")
    reservation_open_day = new_settings.get("reservation_open_day", "Saturday")
    reservation_open_time = new_settings.get("reservation_open_time", "16:30")
    reservation_close_day = new_settings.get("reservation_close_day", "Sunday")
    reservation_close_time = new_settings.get("reservation_close_time", "22:00")

    # Get content items for the content management tab
    cur = db.execute("SELECT content_key, content_value FROM website_content")
    content_items = {}
    meal_rules_list = []
    for row in cur.fetchall():
        # Convert HTML back to markdown for editing
        content = row["content_value"]
        content_key = row["content_key"]

        # Special handling for meal_rules - convert bulleted list back to lines
        if content_key == 'meal_rules':
            # Remove <ul> and </ul> tags
            content = content.replace('<ul>', '').replace('</ul>', '')
            import re
            # Use a more robust regex that captures everything between <li> and </li>
            rules = re.findall(r'<li>(.*?)</li>', content, flags=re.DOTALL)
            meal_rules_list = [rule.strip() for rule in rules if rule.strip()]
            # Also provide the joined string for backward compatibility
            content = '\n'.join(meal_rules_list)
        else:
            # Convert HTML links back to markdown
            import re
            content = re.sub(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', r'[\2](\1)', content)
            # Convert HTML bold back to markdown
            content = re.sub(r'<strong>([^<]+)</strong>', r'**\1**', content)
            # Convert HTML italic back to markdown
            content = re.sub(r'<em>([^<]+)</em>', r'*\1*', content)
            # Convert HTML line breaks back to newlines
            content = content.replace('<br>', '\n')

        content_items[content_key] = content
    # Add the meal_rules_list for the template
    content_items['meal_rules_list'] = meal_rules_list

    return render_template(
        "admin.html",
        users=users,
        reservations_by_slot=reservations_by_slot,
        week_list=week_list,
        admin_accounts=admin_accounts,
        is_super_admin=is_super_admin,
        is_admin=is_admin,
        weekly_slots=weekly_slots,
        reservation_status=reservation_status,
        reservation_open_day=reservation_open_day,
        reservation_open_time=reservation_open_time,
        reservation_close_day=reservation_close_day,
        reservation_close_time=reservation_close_time,
        is_pub_slot=is_pub_slot,
        content_items=content_items,
    )


@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    db = get_db()
    manual_status = request.form.get("manual_status", "auto").strip()
    open_day = request.form.get("reservation_open_day", "").strip()
    open_time = request.form.get("reservation_open_time", "").strip()
    close_day = request.form.get("reservation_close_day", "").strip()
    close_time = request.form.get("reservation_close_time", "").strip()
    db.execute(
        "REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("reservation_status", manual_status),
    )
    db.execute(
        "REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("reservation_open_day", open_day),
    )
    db.execute(
        "REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("reservation_open_time", open_time),
    )
    db.execute(
        "REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("reservation_close_day", close_day),
    )
    db.execute(
        "REPLACE INTO settings (key, value) VALUES (?, ?)",
        ("reservation_close_time", close_time),
    )
    db.commit()
    flash("Settings updated.", "success")
    return redirect(url_for("admin"))


# ---------------------------
# User Routes
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        netid = request.form.get("netid", "").strip().lower()
        
        # Input validation
        if not netid:
            flash("NetID is required.", "danger")
            return render_template("login.html")
        
        if len(netid) > 20 or not re.match(r'^[a-zA-Z0-9_-]+$', netid):
            flash("Invalid NetID format.", "danger")
            return render_template("login.html")
        
        try:
            db = get_db()
            cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
            user = cur.fetchone()
            if user:
                session["netid"] = netid
                session["user_login_time"] = datetime.now().isoformat()
                flash("Logged in successfully.", "success")
                return redirect(url_for("index"))
            else:
                flash("NetID not recognized. Please contact the administrator.", "danger")
        except Exception as e:
            logging.error(f"User login error: {e}")
            flash("An error occurred during login. Please try again.", "danger")
    
    return render_template("login.html")


@app.route("/guest_login", methods=["GET"])
def guest_login():
    session["netid"] = "guest"
    flash("Logged in as guest.", "info")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@cache.memoize(timeout=60)  # Cache for 1 minute
def get_meal_slots_data(start_date, end_date):
    """Get meal slots data for the given date range."""
    try:
        db = get_db()
        cur = db.execute(
            "SELECT * FROM meal_slots WHERE date BETWEEN ? AND ? ORDER BY date",
            (start_date.isoformat(), end_date.isoformat()),
        )
        return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        logging.error(f"Error getting meal slots data: {e}")
        return []


@cache.memoize(timeout=60)
def get_slot_counts(start_date, end_date):
    """Get counts for each meal slot in the given date range."""
    try:
        db = get_db()
        cur = db.execute(
            """
            SELECT meal_slot_id, COUNT(*) as count
            FROM reservations r
            JOIN meal_slots ms ON r.meal_slot_id = ms.id
            WHERE ms.date BETWEEN ? AND ?
            GROUP BY meal_slot_id
            """,
            (start_date.isoformat(), end_date.isoformat()),
        )
        counts = {}
        for row in cur.fetchall():
            counts[str(row["meal_slot_id"])] = row["count"]
        return counts
    except Exception as e:
        logging.error(f"Error getting slot counts: {e}")
        return {}


@cache.memoize(timeout=30)
def get_user_reservations(netid, start_date, end_date):
    """Get reservations for a specific user in the given date range."""
    if not netid:
        return set()
    db = get_db()
    cur = db.execute(
        """
        SELECT meal_slot_id FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (netid, start_date.isoformat(), end_date.isoformat()),
    )
    return {str(row["meal_slot_id"]) for row in cur.fetchall()}


@cache.memoize(timeout=60)
def get_user_current_meals(netid, start_date, end_date):
    """Get current meals for a specific user."""
    db = get_db()
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        ORDER BY ms.date, ms.meal_type
        """,
        (netid, start_date.isoformat(), end_date.isoformat()),
    )
    return [dict(row) for row in cur.fetchall()]


@cache.memoize(timeout=60)
def check_user_has_pub_current(netid, start_date, end_date):
    """Check if user has a pub reservation in the current week."""
    db = get_db()
    cur = db.execute(
        "SELECT ms.* FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id "
        "WHERE r.netid = ? AND ms.date BETWEEN ? AND ?",
        (netid, start_date.isoformat(), end_date.isoformat()),
    )
    rows = cur.fetchall()
    return any(is_pub_slot(row) for row in rows)


@cache.memoize(timeout=60)
def get_manual_pub_info(netid, start_date, end_date):
    """Get manual pub info for a user."""
    db = get_db()
    cur = db.execute(
        "SELECT ms.date, r.added_by FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id "
        "WHERE r.netid = ? AND ms.meal_type = 'dinner' AND ms.date BETWEEN ? AND ? AND r.added_by IS NOT NULL",
        (netid, start_date.isoformat(), end_date.isoformat()),
    )
    pub_info = cur.fetchone()
    if pub_info:
        d = datetime.strptime(pub_info["date"], "%Y-%m-%d").date()
        pub_info = dict(pub_info)
        pub_info["dayname"] = d.strftime("%A")
    return pub_info


@cache.memoize(timeout=120)
def get_reservation_settings():
    """Get reservation settings from the database."""
    db = get_db()
    cur = db.execute(
        "SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)",
        (
            "reservation_status",
            "reservation_open_day",
            "reservation_open_time",
            "reservation_close_day",
            "reservation_close_time",
        ),
    )
    return {row["key"]: row["value"] for row in cur.fetchall()}


@app.route("/")
@login_required
def index():
    generate_next_week_meal_slots()

    # Get date ranges
    today = date.today()
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=6)
    next_monday = current_week_start + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)

    # User info
    user_netid = session["netid"]

    # Use cached functions for expensive database operations
    meal_slots = get_meal_slots_data(next_monday, next_sunday)
    slot_counts = get_slot_counts(next_monday, next_sunday)
    user_reservations = get_user_reservations(user_netid, next_monday, next_sunday)
    current_meals = get_user_current_meals(
        user_netid, current_week_start, current_week_end
    )
    user_has_pub_current = check_user_has_pub_current(
        user_netid, current_week_start, current_week_end
    )
    manual_pub_info = get_manual_pub_info(user_netid, next_monday, next_sunday)

    # Group meal slots by date
    slots_by_date = {}
    for slot in meal_slots:
        slots_by_date.setdefault(slot["date"], []).append(slot)

    # Sort slots within each day
    for day, slots in slots_by_date.items():
        day_obj = datetime.strptime(day, "%Y-%m-%d").date()
        order = (
            {"breakfast": 1, "lunch": 2, "dinner": 3}
            if day_obj.weekday() < 5
            else {"brunch": 1, "dinner": 2}
        )
        slots.sort(key=lambda s: order.get(s["meal_type"].lower(), 99))

    # Build a dictionary of meal_slots keyed by id (as a string)
    meal_slots_dict = {str(slot["id"]): slot for slot in meal_slots}

    # Determine if the user has a pub night reservation
    user_has_pub_selected = any(
        is_pub_slot(meal_slots_dict[slot_id])
        for slot_id in user_reservations
        if slot_id in meal_slots_dict
    )

    # Get reservation settings
    settings = get_reservation_settings()
    reservation_status = settings.get("reservation_status", "auto")
    signup_open = False
    next_signup_open = None
    next_signup_close = None
    now_eastern = datetime.now(ZoneInfo("America/New_York"))

    if reservation_status == "auto":
        try:
            open_time_str = settings.get("reservation_open_time")
            close_time_str = settings.get("reservation_close_time")
            if not open_time_str or not close_time_str:
                raise ValueError("Missing reservation_open_time or reservation_close_time in settings.")
            target_time_open = datetime.strptime(open_time_str, "%H:%M").time()
            target_time_close = datetime.strptime(close_time_str, "%H:%M").time()
            weekday_mapping = {
                "Monday": 0,
                "Tuesday": 1,
                "Wednesday": 2,
                "Thursday": 3,
                "Friday": 4,
                "Saturday": 5,
                "Sunday": 6,
            }
            open_day_str = settings.get("reservation_open_day", "Saturday")
            close_day_str = settings.get("reservation_close_day", "Sunday")
            open_weekday = weekday_mapping.get(open_day_str, 5)
            close_weekday = weekday_mapping.get(close_day_str, 6)
            # Compute current week's Monday
            current_monday = now_eastern.date() - timedelta(days=now_eastern.weekday())
            open_date = current_monday + timedelta(days=open_weekday)
            close_date = current_monday + timedelta(days=close_weekday)
            open_dt = datetime.combine(
                open_date, target_time_open, tzinfo=ZoneInfo("America/New_York")
            )
            close_dt = datetime.combine(
                close_date, target_time_close, tzinfo=ZoneInfo("America/New_York")
            )

            if now_eastern < open_dt:
                signup_open = False
                next_signup_open = open_dt
                next_signup_close = close_dt
            elif open_dt <= now_eastern < close_dt:
                signup_open = True
                next_signup_open = open_dt + timedelta(weeks=1)
                next_signup_close = close_dt + timedelta(weeks=1)
            else:
                signup_open = False
                next_signup_open = open_dt + timedelta(weeks=1)
                next_signup_close = close_dt + timedelta(weeks=1)
        except Exception as e:
            print("Error parsing auto settings:", e)
    elif reservation_status == "open":
        signup_open = True
    elif reservation_status == "closed":
        signup_open = False

    meal_period_start = None
    meal_period_end = None
    if next_signup_close:
        days_until_monday = (7 - next_signup_close.weekday()) % 7
        if days_until_monday == 0:
            days_until_monday = 7
        meal_period_start = next_signup_close + timedelta(days=days_until_monday)
        meal_period_end = meal_period_start + timedelta(days=6)

    # Get website content
    website_content = get_website_content()

    return render_template(
        "index.html",
        slots_by_date=slots_by_date,
        current_meals=current_meals,
        slot_counts=slot_counts,
        signup_open=signup_open,
        next_signup_open=next_signup_open,
        next_signup_close=next_signup_close,
        user_reservations=user_reservations,
        meal_period_start=meal_period_start,
        meal_period_end=meal_period_end,
        user_has_pub_selected=user_has_pub_selected,
        user_has_pub_current=user_has_pub_current,
        manual_pub_info=manual_pub_info,
        meal_slots_dict=meal_slots_dict,
        website_content=website_content,
    )


@app.route("/reserve", methods=["POST"])
@login_required
def reserve():
    if session.get("netid") == "guest":
        flash("Guest users cannot submit reservations.", "danger")
        return redirect(url_for("index"))
    
    # Validate input
    selected_slots_raw = request.form.getlist("meal_slot")
    if not selected_slots_raw:
        flash("No meal slots selected.", "danger")
        return redirect(url_for("index"))
    
    # Validate slot IDs are integers
    selected_slots = set()
    for slot_id in selected_slots_raw:
        try:
            slot_id_int = int(slot_id)
            if slot_id_int > 0:
                selected_slots.add(str(slot_id_int))
        except (ValueError, TypeError):
            flash("Invalid meal slot selection.", "danger")
            return redirect(url_for("index"))

    # Use server timestamp instead of client timestamp
    server_timestamp = datetime.now(ZoneInfo("America/New_York")).isoformat()

    try:
        db = get_db()
        user_netid = session["netid"]
        today = date.today()
        next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
        next_sunday = next_monday + timedelta(days=6)
    except Exception as e:
        logging.error(f"Database connection error in reserve: {e}")
        flash("Database connection error. Please try again.", "danger")
        return redirect(url_for("index"))

    # -- Define current_week_start / current_week_end so we can use them below --
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=6)

    # Get all manual pub reservations (admin-added pub night) for this week.
    cur = db.execute(
        "SELECT meal_slot_id FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id "
        "WHERE r.netid = ? AND ms.meal_type = 'dinner' AND ms.date BETWEEN ? AND ? AND r.added_by IS NOT NULL",
        (user_netid, next_monday.isoformat(), next_sunday.isoformat()),
    )
    manual_pub_slots = {str(row["meal_slot_id"]) for row in cur.fetchall()}
    manual_pub_exists = len(manual_pub_slots) > 0

    # Always allow a total of 2 reservations.
    total_allowed = 2

    # Calculate how many additional (non-admin-added) slots are being selected.
    additional_selected = len(selected_slots - manual_pub_slots)
    if manual_pub_exists and additional_selected > 1:
        flash(
            "You may only select one additional meal in addition to your pub night reservation.",
            "danger",
        )
        return redirect(url_for("index"))
    if not manual_pub_exists and len(selected_slots) > total_allowed:
        flash(
            f"You cannot select more than {total_allowed} meal(s) this week.", "danger"
        )
        return redirect(url_for("index"))

    pub_count = 0
    for slot_id in selected_slots:
        cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (slot_id,))
        meal_slot = cur.fetchone()
        if meal_slot and is_pub_slot(meal_slot):
            pub_count += 1
    if pub_count > 1:
        flash("You cannot select more than 1 pub night.", "danger")
        return redirect(url_for("index"))

    cur = db.execute(
        """
        SELECT meal_slot_id, added_by FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (user_netid, next_monday.isoformat(), next_sunday.isoformat()),
    )
    current_reservations = {}
    for row in cur.fetchall():
        current_reservations[str(row["meal_slot_id"])] = row["added_by"]

    # Do not allow deletion of admin-added pub reservations.
    to_delete = {
        slot
        for slot in current_reservations
        if slot not in selected_slots and slot not in manual_pub_slots
    }
    to_add = selected_slots - set(current_reservations.keys())

    for slot_id in to_delete:
        try:
            db.execute(
                "DELETE FROM reservations WHERE netid = ? AND meal_slot_id = ?",
                (user_netid, slot_id),
            )
        except Exception as e:
            logging.error(f"Error deleting reservation for slot {slot_id}: {e}")
            flash(f"Error deleting reservation for slot {slot_id}: {str(e)}", "danger")
            return redirect(url_for("index"))
    for slot_id in to_add:
        try:
            cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (slot_id,))
            meal_slot = cur.fetchone()
            if not meal_slot:
                flash(f"Meal slot {slot_id} not found.", "danger")
                return redirect(url_for("index"))
            cur = db.execute(
                "SELECT COUNT(*) as count FROM reservations WHERE meal_slot_id = ?",
                (slot_id,),
            )
            count = cur.fetchone()["count"]
            if count >= meal_slot["capacity"]:
                flash(
                    f"{meal_slot['meal_type'].capitalize()} on {meal_slot['date']} is already full.",
                    "danger",
                )
                return redirect(url_for("index"))
            db.execute(
                "INSERT INTO reservations (netid, meal_slot_id, timestamp) VALUES (?, ?, ?)",
                (user_netid, slot_id, server_timestamp),
            )
        except Exception as e:
            logging.error(f"Error adding reservation for slot {slot_id}: {e}")
            flash(f"Error adding reservation for slot {slot_id}: {str(e)}", "danger")
            return redirect(url_for("index"))
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error("Database commit failed: " + str(e))
        flash("Database commit failed: " + str(e), "danger")
        return redirect(url_for("index"))
    flash("Reservations updated successfully.", "success")

    # Invalidate caches after reservation changes
    cache.delete_memoized(get_slot_counts, next_monday, next_sunday)
    cache.delete_memoized(get_user_reservations, user_netid, next_monday, next_sunday)
    # Use the newly defined current_week_start/current_week_end here:
    cache.delete_memoized(
        get_user_current_meals, user_netid, current_week_start, current_week_end
    )
    cache.delete_memoized(
        check_user_has_pub_current, user_netid, current_week_start, current_week_end
    )
    cache.delete_memoized(get_manual_pub_info, user_netid, next_monday, next_sunday)

    return redirect(url_for("index"))


@app.route("/meal_counts")
def meal_counts():
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)

    # Use the cached function
    counts = get_slot_counts(next_monday, next_sunday)
    return jsonify(counts)


@app.route("/admin/upload_emails", methods=["POST"])
@admin_required
def admin_upload_emails():
    db = get_db()
    if "emails_file" in request.files:
        f = request.files["emails_file"]
        if f:
            try:
                content = f.read().decode("utf-8")
            except Exception as e:
                flash("Error reading file.", "danger")
                return redirect(url_for("admin"))
            f_io = io.StringIO(content)
            reader = csv.reader(f_io)
            added = []
            updated = []
            skipped = []
            for row in reader:
                if len(row) < 2:
                    continue
                netid = row[0].strip().lower()
                name = row[1].strip()
                if not netid:
                    continue
                cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
                existing = cur.fetchone()
                try:
                    if existing:
                        db.execute(
                            "UPDATE users SET name = ? WHERE netid = ?", (name, netid)
                        )
                        updated.append(netid)
                    else:
                        db.execute(
                            "INSERT INTO users (netid, name) VALUES (?, ?)",
                            (netid, name),
                        )
                        added.append(netid)
                except sqlite3.IntegrityError:
                    skipped.append(netid)
            db.commit()
            flash(
                f"Added: {len(added)}. Updated: {len(updated)}. Skipped: {len(skipped)}.",
                "success",
            )
    return redirect(url_for("admin"))


@app.route("/admin/add_user", methods=["POST"])
@admin_required
def admin_add_user():
    db = get_db()
    netids_str = request.form.get("new_netid", "")
    netids = [x.strip().lower() for x in netids_str.split(",") if x.strip()]
    if not netids:
        flash("No netid provided.", "danger")
        return redirect(url_for("admin"))
    added = []
    skipped = []
    for netid in netids:
        try:
            db.execute("INSERT INTO users (netid) VALUES (?)", (netid,))
            added.append(netid)
        except sqlite3.IntegrityError:
            skipped.append(netid)
    db.commit()
    flash(f"Added users: {', '.join(added)}. Skipped: {', '.join(skipped)}", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    db = get_db()
    netids_str = request.form.get("delete_netid", "")
    netids = [x.strip().lower() for x in netids_str.split(",") if x.strip()]
    if not netids:
        flash("No netid provided.", "danger")
        return redirect(url_for("admin"))
    deleted = []
    not_found = []
    for netid in netids:
        cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
        if cur.fetchone():
            db.execute("DELETE FROM reservations WHERE netid = ?", (netid,))
            db.execute("DELETE FROM users WHERE netid = ?", (netid,))
            deleted.append(netid)
        else:
            not_found.append(netid)
    db.commit()
    flash(
        f"Deleted: {', '.join(deleted)}. Not found: {', '.join(not_found)}", "success"
    )
    return redirect(url_for("admin"))


@app.route("/admin/bulk_delete_users", methods=["POST"])
@admin_required
def admin_bulk_delete_users():
    db = get_db()
    if "delete_netids_file" in request.files:
        f = request.files["delete_netids_file"]
        if f:
            try:
                content = f.read().decode("utf-8")
            except Exception as e:
                flash("Error reading file: " + str(e), "danger")
                return redirect(url_for("admin"))
            netid_candidates = re.split(r"[\n,]+", content)
            valid_netids = []
            for netid in netid_candidates:
                netid = netid.strip().lower()
                if netid:
                    valid_netids.append(netid)
            removed = []
            not_found = []
            for netid in valid_netids:
                cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
                if cur.fetchone():
                    db.execute("DELETE FROM reservations WHERE netid = ?", (netid,))
                    db.execute("DELETE FROM users WHERE netid = ?", (netid,))
                    removed.append(netid)
                else:
                    not_found.append(netid)
            db.commit()
            flash(
                f"Bulk deletion complete: {len(removed)} netIDs removed, {len(not_found)} netIDs not found.",
                "success",
            )
        else:
            flash("No file selected.", "danger")
    else:
        flash("No file uploaded.", "danger")
    return redirect(url_for("admin"))


# ---------------------------
# Route for adding a reservation manually (for any meal slot) by an admin.
# ---------------------------
@app.route("/admin/add_reservation", methods=["POST"])
@admin_required
def admin_add_reservation():
    try:
        db = get_db()
        netids_str = request.form.get("reservation_netid", "")
        meal_slot_id = request.form.get("meal_slot_id", "").strip()
        
        # Input validation
        if not meal_slot_id:
            flash("Meal slot ID is required.", "danger")
            return redirect(url_for("admin"))
        
        try:
            meal_slot_id_int = int(meal_slot_id)
            if meal_slot_id_int <= 0:
                raise ValueError("Invalid meal slot ID")
        except (ValueError, TypeError):
            flash("Invalid meal slot ID.", "danger")
            return redirect(url_for("admin"))
        
        # Validate netids
        netids = []
        for netid in netids_str.split(","):
            netid = netid.strip().lower()
            if netid and len(netid) <= 20 and re.match(r'^[a-zA-Z0-9_-]+$', netid):
                netids.append(netid)
        
        if not netids:
            flash("No valid NetIDs provided.", "danger")
            return redirect(url_for("admin"))
        
        # Check if meal slot exists
        cur = db.execute("SELECT id FROM meal_slots WHERE id = ?", (meal_slot_id_int,))
        if not cur.fetchone():
            flash("Meal slot not found.", "danger")
            return redirect(url_for("admin"))
        
        added = []
        skipped = []
        server_timestamp = datetime.now(ZoneInfo("America/New_York")).isoformat()
        
        # ADMIN OVERRIDE: Do not check for capacity here. This allows manual overfilling.
        for netid in netids:
            try:
                db.execute(
                    "INSERT INTO reservations (netid, meal_slot_id, timestamp, added_by) VALUES (?, ?, ?, ?)",
                    (netid, meal_slot_id_int, server_timestamp, session["admin_username"]),
                )
                added.append(netid)
            except sqlite3.IntegrityError:
                skipped.append(netid)
        
        db.commit()
        flash(
            f"Added reservations for: {', '.join(added)}. Skipped: {', '.join(skipped)}",
            "success",
        )
        
    except Exception as e:
        logging.error(f"Error adding reservation: {e}")
        flash("An error occurred while adding reservations.", "danger")
    
    return redirect(url_for("admin"))


@app.route("/admin/delete_reservation/<int:reservation_id>", methods=["POST"])
@admin_required
def admin_delete_reservation(reservation_id):
    try:
        db = get_db()
        
        # Check if reservation exists before deleting
        cur = db.execute("SELECT id FROM reservations WHERE id = ?", (reservation_id,))
        if not cur.fetchone():
            flash("Reservation not found.", "danger")
            return redirect(url_for("admin"))
        
        db.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))
        db.commit()
        flash("Reservation deleted.", "success")
        
    except Exception as e:
        logging.error(f"Error deleting reservation {reservation_id}: {e}")
        flash("An error occurred while deleting the reservation.", "danger")
    
    return redirect(url_for("admin"))


# ---------------------------
# Content Management Routes
# ---------------------------
def parse_markdown(text, content_key=None):
    """Parse basic markdown formatting in text."""
    import re
    
    # Convert markdown links to HTML
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
    
    # Convert bold text
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    
    # Convert italic text
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    
    # Special handling for meal_rules - convert each line to a bulleted list item
    if content_key == 'meal_rules':
        lines = text.split('\n')
        bulleted_lines = []
        for line in lines:
            line = line.strip()
            if line:  # Only add non-empty lines
                bulleted_lines.append(f'<li>{line}</li>')
        if bulleted_lines:
            text = f'<ul>{"".join(bulleted_lines)}</ul>'
        else:
            text = ''
    else:
        # Convert line breaks to HTML for other content
        text = text.replace('\n', '<br>')
    
    return text




@app.route("/admin/delete_content/<content_key>", methods=["POST"])
@admin_required
def admin_delete_content(content_key):
    db = get_db()
    try:
        db.execute("DELETE FROM website_content WHERE content_key = ?", (content_key,))
        db.commit()
        flash("Content deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting content: {str(e)}", "danger")
    return redirect(url_for("admin_content"))


# ---------------------------
# Purge Functionality
# ---------------------------
@app.route("/admin/purge", methods=["POST"])
@admin_required
def admin_purge():
    db = get_db()
    try:
        # Create archive tables if they don't exist
        db.execute("""
            CREATE TABLE IF NOT EXISTS archived_users (
                netid TEXT PRIMARY KEY,
                name TEXT,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        db.execute("""
            CREATE TABLE IF NOT EXISTS archived_meal_slots (
                id INTEGER PRIMARY KEY,
                date TEXT NOT NULL,
                meal_type TEXT NOT NULL,
                capacity INTEGER NOT NULL DEFAULT 25,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        db.execute("""
            CREATE TABLE IF NOT EXISTS archived_reservations (
                id INTEGER PRIMARY KEY,
                netid TEXT NOT NULL,
                meal_slot_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                added_by TEXT,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Archive all data before deletion
        db.execute("""
            INSERT INTO archived_users (netid, name)
            SELECT netid, name FROM users
        """)
        
        db.execute("""
            INSERT INTO archived_meal_slots (id, date, meal_type, capacity)
            SELECT id, date, meal_type, capacity FROM meal_slots
        """)
        
        db.execute("""
            INSERT INTO archived_reservations (id, netid, meal_slot_id, timestamp, added_by)
            SELECT id, netid, meal_slot_id, timestamp, added_by FROM reservations
        """)
        
        # Delete all users except admins
        db.execute("DELETE FROM users")
        
        # Delete all reservations
        db.execute("DELETE FROM reservations")
        
        # Delete all meal slots
        db.execute("DELETE FROM meal_slots")
        
        # Clear cache
        cache.clear()
        
        db.commit()
        flash("All users, reservations, and meal slots have been archived and purged. The system is ready for a new semester.", "success")
    except Exception as e:
        flash(f"Error during purge: {str(e)}", "danger")
    
    return redirect(url_for("admin"))


@app.route("/admin/download_archive")
@admin_required
def admin_download_archive():
    """Download an archive file containing all archived data."""
    db = get_db()
    
    try:
        import csv
        import io
        from datetime import datetime
        
        # Create a string buffer to hold the CSV data
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header with archive timestamp
        writer.writerow(['Charter Meals Archive'])
        writer.writerow(['Generated on:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        
        # Export archived users
        writer.writerow(['ARCHIVED USERS'])
        writer.writerow(['NetID', 'Name', 'Archived At'])
        cur = db.execute("SELECT netid, name, archived_at FROM archived_users ORDER BY netid")
        for row in cur.fetchall():
            writer.writerow([row['netid'], row['name'], row['archived_at']])
        writer.writerow([])
        
        # Export archived meal slots
        writer.writerow(['ARCHIVED MEAL SLOTS'])
        writer.writerow(['ID', 'Date', 'Meal Type', 'Capacity', 'Archived At'])
        cur = db.execute("SELECT id, date, meal_type, capacity, archived_at FROM archived_meal_slots ORDER BY date, meal_type")
        for row in cur.fetchall():
            writer.writerow([row['id'], row['date'], row['meal_type'], row['capacity'], row['archived_at']])
        writer.writerow([])
        
        # Export archived reservations
        writer.writerow(['ARCHIVED RESERVATIONS'])
        writer.writerow(['ID', 'NetID', 'Meal Slot ID', 'Timestamp', 'Added By', 'Archived At'])
        cur = db.execute("SELECT id, netid, meal_slot_id, timestamp, added_by, archived_at FROM archived_reservations ORDER BY timestamp")
        for row in cur.fetchall():
            writer.writerow([row['id'], row['netid'], row['meal_slot_id'], row['timestamp'], row['added_by'], row['archived_at']])
        
        # Get the CSV data
        csv_data = output.getvalue()
        output.close()
        
        # Create response with CSV data
        from flask import Response
        response = Response(csv_data, mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=charter_meals_archive_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        flash(f"Error generating archive: {str(e)}", "danger")
        return redirect(url_for("admin"))


@app.route("/admin/clear_archive", methods=["POST"])
@admin_required
def admin_clear_archive():
    """Clear all archived data."""
    db = get_db()
    try:
        db.execute("DELETE FROM archived_users")
        db.execute("DELETE FROM archived_meal_slots")
        db.execute("DELETE FROM archived_reservations")
        db.commit()
        flash("All archived data has been cleared.", "success")
    except Exception as e:
        flash(f"Error clearing archive: {str(e)}", "danger")
    
    return redirect(url_for("admin"))

@app.route("/admin/backup_database")
@admin_required
def admin_backup_database():
    """Create a backup of the current database."""
    try:
        import shutil
        from datetime import datetime
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"charter_meals_backup_{timestamp}.db"
        
        # Copy database file
        shutil.copy2(app.config["DATABASE"], backup_filename)
        
        # Create response with backup file
        response = Response(open(backup_filename, 'rb').read(), mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = f'attachment; filename={backup_filename}'
        
        # Clean up backup file after sending
        import os
        os.remove(backup_filename)
        
        return response
        
    except Exception as e:
        logging.error(f"Database backup failed: {e}")
        flash(f"Error creating backup: {str(e)}", "danger")
        return redirect(url_for("admin"))


# ---------------------------
# Helper function to get website content
# ---------------------------
@cache.memoize(timeout=300)  # Cache for 5 minutes
def get_website_content():
    """Get all website content from the database."""
    db = get_db()
    cur = db.execute("SELECT content_key, content_value FROM website_content")
    return {row["content_key"]: row["content_value"] for row in cur.fetchall()}


@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for("admin_login"))

@app.errorhandler(404)
def not_found(error):
    flash("Page not found.", "danger")
    return redirect(url_for("index"))

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {error}")
    flash("An internal server error occurred. Please try again later.", "danger")
    return redirect(url_for("index"))

@app.route("/health")
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Test database connection
        db = get_db()
        db.execute("SELECT 1")
        
        # Test cache connection (if Redis is available)
        try:
            cache.set("health_check", "ok", timeout=10)
            cache_status = "ok"
        except Exception:
            cache_status = "error"
        
        return jsonify({
            "status": "healthy",
            "version": "2.0.1",
            "database": "ok",
            "cache": cache_status,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "version": "2.0.1",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


# ---------------------------
# Context Processor for Version
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
            # Use the VERSION file to version static assets
            version_path = os.path.join(os.path.dirname(__file__), "VERSION")
            with open(version_path, "r") as vf:
                version = vf.read().strip().replace(".", "_")
        except Exception:
            # If VERSION file can't be read, use current timestamp
            version = str(int(time.time()))

        return url_for("static", filename=filename) + "?v=" + version

    return dict(asset_url_for=asset_url_for)


if __name__ == "__main__":
    app.run(debug=True)
