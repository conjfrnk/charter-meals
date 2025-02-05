import os
import re
import sqlite3
import logging
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
import csv, io
from werkzeug.security import generate_password_hash, check_password_hash

# --- Security Extensions ---
from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
    SESSION_COOKIE_SECURE=True,  # Only transmit cookie over HTTPS.
    SESSION_COOKIE_HTTPONLY=True,  # Disallow JavaScript access.
    SESSION_COOKIE_SAMESITE="Lax",
)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Global variable for caching meal slot generation
last_slot_generation = None

# Initialize Talisman with an updated Content Security Policy and enforce HTTPS.
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://code.jquery.com", "'unsafe-inline'"],
    "style-src": ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
)

# Enable CSRF Protection
csrf = CSRFProtect(app)

# Initialize Rate Limiter (adjusted for higher traffic)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="redis://localhost:6379/0",
)
limiter.init_app(app)

# Database location as specified
app.config["DATABASE"] = "/var/www/data/meals.db"


# ---------------------------
# Database Helpers
# ---------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
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
    # Create default admin account (username: admin, password: admin)
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
# Application Helpers
# ---------------------------
def generate_next_week_meal_slots():
    global last_slot_generation
    # Run only if more than 6 hours have passed
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
        if d.weekday() < 5:
            meals = ["breakfast", "lunch", "dinner"]
        else:
            meals = ["brunch", "dinner"]
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


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "netid" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


# ---------------------------
# Admin Authentication System
# ---------------------------
def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "admin_username" not in session:
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


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


# --- End Admin Authentication System ---


# ---------------------------
# Admin Dashboard Route
# ---------------------------
@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    db = get_db()
    cur = db.execute("SELECT netid FROM users ORDER BY netid")
    users = cur.fetchall()
    cur = db.execute(
        """
        SELECT r.id as reservation_id, r.netid, ms.id as meal_slot_id, ms.date, ms.meal_type, r.timestamp
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
            reservations_by_slot[key] = {
                "meal_slot_id": res["meal_slot_id"],
                "date": res["date"],
                "meal_type": res["meal_type"],
                "reservations": [],
            }
        reservations_by_slot[key]["reservations"].append(res)
    cur = db.execute("SELECT DISTINCT date FROM meal_slots ORDER BY date DESC")
    dates = [
        datetime.strptime(row["date"], "%Y-%m-%d").date() for row in cur.fetchall()
    ]
    weeks = set()
    for d in dates:
        monday = d - timedelta(days=d.weekday())
        weeks.add(monday)
    week_list = sorted(list(weeks), reverse=True)
    cur = db.execute("SELECT username FROM admins ORDER BY username")
    admin_accounts = [row["username"] for row in cur.fetchall()]
    is_super_admin = session.get("admin_username") == "admin"
    return render_template(
        "admin.html",
        users=users,
        reservations_by_slot=reservations_by_slot,
        week_list=week_list,
        admin_accounts=admin_accounts,
        is_super_admin=is_super_admin,
    )


# ---------------------------
# User Routes
# ---------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        netid = request.form["netid"].strip().lower()
        if not re.match(r"^[a-z]{2}\d{4}$", netid):
            flash(
                "Invalid netid format. Must be two letters followed by four digits (e.g. ab1234).",
                "danger",
            )
            return redirect(url_for("login"))
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
    slots_by_date = {}
    for slot in meal_slots:
        slots_by_date.setdefault(slot["date"], []).append(slot)
    for day, slots in slots_by_date.items():
        day_obj = datetime.strptime(day, "%Y-%m-%d").date()
        if day_obj.weekday() < 5:
            order = {"breakfast": 1, "lunch": 2, "dinner": 3}
        else:
            order = {"brunch": 1, "dinner": 2}
        slots.sort(key=lambda s: order.get(s["meal_type"], 99))
    cur = db.execute(
        """
        SELECT meal_slot_id FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (session["netid"], next_monday.isoformat(), next_sunday.isoformat()),
    )
    user_reservations = {str(row["meal_slot_id"]) for row in cur.fetchall()}
    this_monday = date.today() - timedelta(days=date.today().weekday())
    this_sunday = this_monday + timedelta(days=6)
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        ORDER BY ms.date, ms.meal_type
        """,
        (session["netid"], this_monday.isoformat(), this_sunday.isoformat()),
    )
    current_meals = cur.fetchall()
    cur = db.execute(
        """
        SELECT r.*, ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.netid = ? AND ms.date BETWEEN ? AND ?
        """,
        (session["netid"], this_monday.isoformat(), this_sunday.isoformat()),
    )
    pub_exists = any(
        (
            row["meal_type"] == "dinner"
            and datetime.strptime(row["date"], "%Y-%m-%d").date().weekday() in [1, 3]
        )
        for row in cur.fetchall()
    )
    eligible_for_pub = not pub_exists
    return render_template(
        "index.html",
        slots_by_date=slots_by_date,
        user_reservations=user_reservations,
        eligible_for_pub=eligible_for_pub,
        current_meals=current_meals,
        slot_counts=slot_counts,
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
        timestamp = datetime.fromisoformat(client_timestamp)
    except ValueError as e:
        flash("Invalid timestamp format: " + str(e), "danger")
        return redirect(url_for("index"))
    db = get_db()
    user_netid = session["netid"]
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
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
    if len(selected_slots) > 2:
        flash("You cannot select more than 2 meals per week.", "danger")
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
        SELECT ms.date, ms.meal_type, r.netid, r.timestamp
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
    writer.writerow(["date", "meal", "netid"])
    for row in rows:
        writer.writerow([row["date"], row["meal_type"], row["netid"]])
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
        SELECT ms.date, ms.meal_type, r.netid, r.timestamp
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        ORDER BY r.timestamp ASC
        """
    )
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "netid"])
    for row in rows:
        writer.writerow([row["date"], row["meal_type"], row["netid"]])
    csv_content = output.getvalue()
    output.close()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=meal_signups_all.csv"},
    )


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
            invalid_netids = []
            for line in lines:
                netid = line.strip().lower()
                if re.match(r"^[a-z]{2}\d{4}$", netid):
                    valid_netids.append(netid)
                else:
                    invalid_netids.append(netid)
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
                f"Added {len(added)} netids. Skipped {len(skipped)} duplicates. Skipped {len(invalid_netids)} invalid netids.",
                "success",
            )
    return redirect(url_for("admin"))


@app.route("/admin/add_user", methods=["POST"])
@admin_required
def admin_add_user():
    db = get_db()
    netid = request.form.get("new_netid", "").strip().lower()
    if netid:
        if not re.match(r"^[a-z]{2}\d{4}$", netid):
            flash(
                "Invalid netid format. Must be two letters followed by four digits (e.g. ab1234).",
                "danger",
            )
            return redirect(url_for("admin"))
        try:
            db.execute("INSERT INTO users (netid) VALUES (?)", (netid,))
            db.commit()
            flash(f"User {netid} added.", "success")
        except sqlite3.IntegrityError:
            flash(f"User {netid} already exists.", "warning")
    else:
        flash("No netid provided.", "danger")
    return redirect(url_for("admin"))


@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    db = get_db()
    netid = request.form.get("delete_netid", "").strip().lower()
    if netid:
        db.execute("DELETE FROM users WHERE netid = ?", (netid,))
        db.commit()
        flash(f"User {netid} deleted.", "success")
    else:
        flash("No netid provided.", "danger")
    return redirect(url_for("admin"))


@app.route("/admin/add_reservation", methods=["POST"])
@admin_required
def admin_add_reservation():
    db = get_db()
    netid = request.form.get("reservation_netid", "").strip().lower()
    meal_slot_id = request.form.get("meal_slot_id", "").strip()
    if not netid or not meal_slot_id:
        flash("Netid and meal slot are required.", "danger")
        return redirect(url_for("admin"))
    timestamp = datetime.now().isoformat()
    try:
        db.execute(
            "INSERT INTO reservations (netid, meal_slot_id, timestamp) VALUES (?, ?, ?)",
            (netid, meal_slot_id, timestamp),
        )
        db.commit()
        flash(f"Reservation for {netid} added to meal slot {meal_slot_id}.", "success")
    except sqlite3.IntegrityError:
        flash("Reservation already exists or error occurred.", "warning")
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


if __name__ == "__main__":
    app.run(debug=True)
