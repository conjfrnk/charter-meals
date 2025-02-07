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
except FileNotFoundError:
    raise RuntimeError(
        "Secret key file not found. Please create a 'secrets.txt' file with a generated secret key."
    )

# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
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

app.config["DATABASE"] = "/var/www/data/meals.db"

Compress(app)

cache_config = {
    "CACHE_TYPE": "simple",
    "CACHE_DEFAULT_TIMEOUT": 300,
}
cache = Cache(app, config=cache_config)


# ---------------------------
# Database Helpers
# ---------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
        g.db.execute("PRAGMA journal_mode=WAL;")
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


# --- Dynamic Migration Command (unchanged) ---
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
        for line in cols.split(","):
            line = line.strip()
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
    for d in days:
        day_str = d.isoformat()
        meals = (
            ["breakfast", "lunch", "dinner"]
            if d.weekday() < 5
            else ["brunch", "dinner"]
        )
        for meal in meals:
            cur = db.execute(
                "SELECT id FROM meal_slots WHERE date = ? AND meal_type = ?",
                (day_str, meal),
            )
            if cur.fetchone() is None:
                db.execute(
                    "INSERT INTO meal_slots (date, meal_type, capacity) VALUES (?, ?, ?)",
                    (day_str, meal, 25),
                )
    db.commit()


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
# Admin Authentication Routes
# ---------------------------
@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        db = get_db()
        cur = db.execute("SELECT * FROM admins WHERE username = ?", (username,))
        admin = cur.fetchone()
        if admin and check_password_hash(admin["password"], password):
            session["admin_username"] = username
            flash("Admin logged in successfully.", "success")
            return redirect(url_for("admin"))
        else:
            flash("Invalid admin credentials.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
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
@admin_required
def admin_add_admin():
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
# Admin Dashboard and Settings
# ---------------------------
@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    db = get_db()
    cur = db.execute("SELECT netid FROM users ORDER BY netid")
    users = cur.fetchall()
    cur = db.execute(
        """
        SELECT r.id as reservation_id, r.netid, ms.id as meal_slot_id, ms.date, ms.meal_type, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
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

    return render_template(
        "admin.html",
        users=users,
        reservations_by_slot=reservations_by_slot,
        week_list=week_list,
        admin_accounts=admin_accounts,
        is_super_admin=is_super_admin,
        weekly_slots=weekly_slots,
        reservation_status=reservation_status,
        reservation_open_day=reservation_open_day,
        reservation_open_time=reservation_open_time,
        reservation_close_day=reservation_close_day,
        reservation_close_time=reservation_close_time,
        is_pub_slot=is_pub_slot,
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
        netid = request.form["netid"].strip()
        db = get_db()
        cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
        user = cur.fetchone()
        if user:
            session["netid"] = netid
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Netid not recognized. Please contact the administrator.", "danger")
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


@app.route("/")
@login_required
def index():
    generate_next_week_meal_slots()
    db = get_db()
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    cur = db.execute(
        "SELECT * FROM meal_slots WHERE date BETWEEN ? AND ? ORDER BY date",
        (next_monday.isoformat(), next_sunday.isoformat()),
    )
    meal_slots = cur.fetchall()
    slot_counts = {}
    for slot in meal_slots:
        cur = db.execute(
            "SELECT COUNT(*) as count FROM reservations WHERE meal_slot_id = ?",
            (slot["id"],),
        )
        slot_counts[str(slot["id"])] = cur.fetchone()["count"]

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
        slots.sort(key=lambda s: order.get(s["meal_type"], 99))

    # Get next-week reservations for the current user.
    cur = db.execute(
        """
        SELECT meal_slot_id FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (session["netid"], next_monday.isoformat(), next_sunday.isoformat()),
    )
    user_reservations = {str(row["meal_slot_id"]) for row in cur.fetchall()}

    # Build a dictionary of meal_slots keyed by id (as a string)
    meal_slots_dict = {str(slot["id"]): slot for slot in meal_slots}

    # Determine if the user has a pub night reservation
    user_has_pub_selected = any(
        is_pub_slot(meal_slots_dict[slot_id])
        for slot_id in user_reservations
        if slot_id in meal_slots_dict
    )

    # Check if the user has been manually added to a pub night
    cur = db.execute(
        "SELECT ms.date, r.added_by FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id WHERE r.netid = ? AND ms.meal_type = 'dinner' AND ms.date BETWEEN ? AND ? AND r.added_by IS NOT NULL",
        (session["netid"], next_monday.isoformat(), next_sunday.isoformat()),
    )
    manual_pub_info = cur.fetchone()

    # Determine if the user is registered for a pub night in the current week.
    current_week_start = today - timedelta(days=today.weekday())
    current_week_end = current_week_start + timedelta(days=6)
    cur = db.execute(
        "SELECT ms.* FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id WHERE r.netid = ? AND ms.date BETWEEN ? AND ?",
        (
            session["netid"],
            current_week_start.isoformat(),
            current_week_end.isoformat(),
        ),
    )
    user_has_pub_current = any(is_pub_slot(row) for row in cur.fetchall())

    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        ORDER BY ms.date, ms.meal_type
        """,
        (
            session["netid"],
            current_week_start.isoformat(),
            current_week_end.isoformat(),
        ),
    )
    current_meals = cur.fetchall()

    # Determine signup status using settings.
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
    settings = {row["key"]: row["value"] for row in cur.fetchall()}
    reservation_status = settings.get("reservation_status", "auto")
    signup_open = False
    next_signup_open = None
    next_signup_close = None
    now_eastern = datetime.now(ZoneInfo("America/New_York"))
    if reservation_status == "auto":
        weekday_mapping = {
            "Monday": 0,
            "Tuesday": 1,
            "Wednesday": 2,
            "Thursday": 3,
            "Friday": 4,
            "Saturday": 5,
            "Sunday": 6,
        }
        try:
            target_weekday_open = weekday_mapping.get(
                settings.get("reservation_open_day", ""), None
            )
            target_weekday_close = weekday_mapping.get(
                settings.get("reservation_close_day", ""), None
            )
            if (
                target_weekday_open is not None
                and target_weekday_close is not None
                and settings.get("reservation_open_time")
                and settings.get("reservation_close_time")
            ):
                target_time_open = datetime.strptime(
                    settings.get("reservation_open_time"), "%H:%M"
                ).time()
                target_time_close = datetime.strptime(
                    settings.get("reservation_close_time"), "%H:%M"
                ).time()
                next_open = next_occurrence(
                    target_weekday_open, target_time_open, now_eastern
                )
                next_close = next_occurrence(
                    target_weekday_close, target_time_close, next_open
                )
                if next_open <= now_eastern < next_close:
                    signup_open = True
                next_signup_open = next_open
                next_signup_close = next_close
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
    )


@app.route("/reserve", methods=["POST"])
@login_required
def reserve():
    if session.get("netid") == "guest":
        flash("Guest users cannot submit reservations.", "danger")
        return redirect(url_for("index"))
    selected_slots = set(request.form.getlist("meal_slot"))
    client_timestamp = request.form.get("client_timestamp")
    if not client_timestamp:
        flash("Client timestamp missing.", "danger")
        return redirect(url_for("index"))
    client_timestamp = client_timestamp.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(client_timestamp)
    except ValueError as e:
        flash("Invalid timestamp format: " + str(e), "danger")
        return redirect(url_for("index"))
    db = get_db()
    user_netid = session["netid"]
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)

    # If the user has been manually added to a pub night, allow only one meal.
    cur = db.execute(
        "SELECT 1 FROM reservations r JOIN meal_slots ms ON r.meal_slot_id = ms.id WHERE r.netid = ? AND ms.meal_type = 'dinner' AND ms.date BETWEEN ? AND ? AND r.added_by IS NOT NULL",
        (user_netid, next_monday.isoformat(), next_sunday.isoformat()),
    )
    manual_pub_exists = cur.fetchone() is not None
    max_allowed = 1 if manual_pub_exists else 2

    if len(selected_slots) > max_allowed:
        flash(f"You cannot select more than {max_allowed} meal(s) this week.", "danger")
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
        SELECT meal_slot_id FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (user_netid, next_monday.isoformat(), next_sunday.isoformat()),
    )
    current_reservations = {str(row["meal_slot_id"]) for row in cur.fetchall()}
    to_delete = current_reservations - selected_slots
    to_add = selected_slots - current_reservations

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
                (user_netid, slot_id, client_timestamp),
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
    return redirect(url_for("index"))


@app.route("/meal_counts")
@cache.cached(timeout=30)
def meal_counts():
    db = get_db()
    cur = db.execute(
        "SELECT meal_slot_id, COUNT(*) as count FROM reservations GROUP BY meal_slot_id"
    )
    counts = {str(row["meal_slot_id"]): row["count"] for row in cur.fetchall()}
    return jsonify(counts)


@app.route("/admin/download_meal_signups/<week_start>")
@admin_required
def admin_download_meal_signups_week(week_start):
    db = get_db()
    week_start_date = datetime.strptime(week_start, "%Y-%m-%d").date()
    week_end_date = week_start_date + timedelta(days=6)
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type, r.netid, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE ms.date BETWEEN ? AND ?
        ORDER BY r.timestamp ASC
        """,
        (week_start_date.isoformat(), week_end_date.isoformat()),
    )
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "netid", "added_by"])
    for row in rows:
        writer.writerow([row["date"], row["meal_type"], row["netid"], row["added_by"]])
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
        SELECT ms.date, ms.meal_type, r.netid, r.timestamp, r.added_by
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        ORDER BY r.timestamp ASC
        """
    )
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "netid", "added_by"])
    for row in rows:
        writer.writerow([row["date"], row["meal_type"], row["netid"], row["added_by"]])
    csv_content = output.getvalue()
    output.close()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=meal_signups_all.csv"},
    )


# ---------------------------
# Updated Admin Routes for User Management
# ---------------------------
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
            lines = content.replace(",", "\n").splitlines()
            valid_netids = []
            for line in lines:
                netid = line.strip().lower()
                if netid:
                    valid_netids.append(netid)
            added = []
            skipped = []
            for netid in valid_netids:
                try:
                    db.execute("INSERT INTO users (netid) VALUES (?)", (netid,))
                    added.append(netid)
                except sqlite3.IntegrityError:
                    skipped.append(netid)
            db.commit()
            flash(
                f"Added {len(added)} netids. Skipped {len(skipped)} duplicates.",
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
# NEW: Route for adding a reservation manually (for pub nights) by an admin.
# ---------------------------
@app.route("/admin/add_reservation", methods=["POST"])
@admin_required
def admin_add_reservation():
    db = get_db()
    netids_str = request.form.get("reservation_netid", "")
    netids = [x.strip().lower() for x in netids_str.split(",") if x.strip()]
    meal_slot_id = request.form.get("meal_slot_id", "").strip()
    if not netids or not meal_slot_id:
        flash("Netid(s) and meal slot are required.", "danger")
        return redirect(url_for("admin"))
    cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (meal_slot_id,))
    meal_slot = cur.fetchone()
    if not meal_slot or not is_pub_slot(meal_slot):
        flash("Reservations can only be added to pub night slots.", "danger")
        return redirect(url_for("admin"))
    timestamp = datetime.now().isoformat()
    added = []
    skipped = []
    cur = db.execute(
        "SELECT COUNT(*) as count FROM reservations WHERE meal_slot_id = ?",
        (meal_slot_id,),
    )
    count = cur.fetchone()["count"]
    capacity = meal_slot["capacity"]
    for netid in netids:
        if count >= capacity:
            flash("Meal slot is full.", "danger")
            break
        try:
            db.execute(
                "INSERT INTO reservations (netid, meal_slot_id, timestamp, added_by) VALUES (?, ?, ?, ?)",
                (netid, meal_slot_id, timestamp, session["admin_username"]),
            )
            added.append(netid)
            count += 1
        except sqlite3.IntegrityError:
            skipped.append(netid)
    db.commit()
    flash(
        f"Added reservations for: {', '.join(added)}. Skipped: {', '.join(skipped)}",
        "success",
    )
    return redirect(url_for("admin"))


@app.route("/admin/delete_reservation/<int:reservation_id>", methods=["POST"])
@admin_required
def admin_delete_reservation(reservation_id):
    db = get_db()
    db.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))
    db.commit()
    flash("Reservation deleted.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for("admin_login"))


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


if __name__ == "__main__":
    app.run(debug=True)
