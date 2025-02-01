import os
import sqlite3
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

# Database location as specified
app.config["DATABASE"] = "/var/www/data/meals.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
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
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    print("Initialized the database.")


@app.template_filter("weekday")
def weekday_filter(date_str):
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    return d.weekday()


@app.template_filter("dayname")
def dayname_filter(date_str):
    d = datetime.strptime(date_str, "%Y-%m-%d").date()
    return d.strftime("%A")


def generate_next_week_meal_slots():
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


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_email" not in session:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def is_pub_slot(meal_slot):
    slot_date = datetime.strptime(meal_slot["date"], "%Y-%m-%d").date()
    return meal_slot["meal_type"] == "dinner" and slot_date.weekday() in [1, 3]


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        db = get_db()
        cur = db.execute("SELECT email FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        if user:
            session["user_email"] = email
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Email not recognized. Please contact the administrator.", "danger")
    return render_template("login.html")


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
        WHERE r.user_email = ? AND ms.date BETWEEN ? AND ?
        """,
        (session["user_email"], next_monday.isoformat(), next_sunday.isoformat()),
    )
    user_reservations = {str(row["meal_slot_id"]) for row in cur.fetchall()}

    # Determine pub eligibility based on current week.
    this_monday = date.today() - timedelta(days=date.today().weekday())
    this_sunday = this_monday + timedelta(days=6)
    cur = db.execute(
        """
        SELECT r.*, ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.user_email = ? AND ms.date BETWEEN ? AND ?
        """,
        (session["user_email"], this_monday.isoformat(), this_sunday.isoformat()),
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
    )


@app.route("/reserve", methods=["POST"])
@login_required
def reserve():
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
    user_email = session["user_email"]

    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    cur = db.execute(
        """
        SELECT meal_slot_id FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.user_email = ? AND ms.date BETWEEN ? AND ?
        """,
        (user_email, next_monday.isoformat(), next_sunday.isoformat()),
    )
    current_reservations = set(str(row["meal_slot_id"]) for row in cur.fetchall())
    to_delete = current_reservations - selected_slots
    to_add = selected_slots - current_reservations

    # Enforce: no more than 2 total selections.
    if len(selected_slots) > 2:
        flash("You cannot select more than 2 meals per week.", "danger")
        return redirect(url_for("index"))
    # Enforce: at most 1 pub night.
    pub_count = 0
    for slot_id in selected_slots:
        cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (slot_id,))
        meal_slot = cur.fetchone()
        if meal_slot and is_pub_slot(meal_slot):
            pub_count += 1
    if pub_count > 1:
        flash("You cannot select more than 1 pub night.", "danger")
        return redirect(url_for("index"))

    for slot_id in to_add:
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

    for slot_id in to_delete:
        try:
            db.execute(
                "DELETE FROM reservations WHERE user_email = ? AND meal_slot_id = ?",
                (user_email, slot_id),
            )
        except Exception as e:
            flash(f"Error deleting reservation for slot {slot_id}: {str(e)}", "danger")
            return redirect(url_for("index"))

    for slot_id in to_add:
        try:
            db.execute(
                "INSERT INTO reservations (user_email, meal_slot_id, timestamp) VALUES (?, ?, ?)",
                (user_email, slot_id, client_timestamp),
            )
        except Exception as e:
            flash(f"Error adding reservation for slot {slot_id}: {str(e)}", "danger")
            return redirect(url_for("index"))

    try:
        db.commit()
    except Exception as e:
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


def check_admin_auth(username, password):
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin"  # Change this to your new password.
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        auth = request.authorization
        if not auth or not check_admin_auth(auth.username, auth.password):
            return abort(401)
        return view(**kwargs)

    return wrapped_view


@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    db = get_db()
    cur = db.execute("SELECT email FROM users ORDER BY email")
    users = cur.fetchall()
    cur = db.execute(
        """
        SELECT r.id as reservation_id, r.user_email, ms.id as meal_slot_id, ms.date, ms.meal_type, r.timestamp
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
    # Get distinct week start dates (Mondays) from meal_slots, newest first.
    cur = db.execute("SELECT DISTINCT date FROM meal_slots ORDER BY date DESC")
    dates = [
        datetime.strptime(row["date"], "%Y-%m-%d").date() for row in cur.fetchall()
    ]
    weeks = set()
    for d in dates:
        monday = d - timedelta(days=d.weekday())
        weeks.add(monday)
    week_list = sorted(list(weeks), reverse=True)
    return render_template(
        "admin.html",
        users=users,
        reservations_by_slot=reservations_by_slot,
        week_list=week_list,
    )


@app.route("/admin/download_meal_signups/<week_start>")
@admin_required
def admin_download_meal_signups_week(week_start):
    db = get_db()
    week_start_date = datetime.strptime(week_start, "%Y-%m-%d").date()
    week_end_date = week_start_date + timedelta(days=6)
    cur = db.execute(
        """
        SELECT ms.date, ms.meal_type, r.user_email, r.timestamp
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
    writer.writerow(["date", "meal", "username"])
    for row in rows:
        username = row["user_email"].split("@")[0]
        writer.writerow([row["date"], row["meal_type"], username])
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
        SELECT ms.date, ms.meal_type, r.user_email, r.timestamp
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        ORDER BY r.timestamp ASC
        """
    )
    rows = cur.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["date", "meal", "username"])
    for row in rows:
        username = row["user_email"].split("@")[0]
        writer.writerow([row["date"], row["meal_type"], username])
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
            emails = [line.strip().lower() for line in lines if line.strip()]
            added = []
            skipped = []
            for email in emails:
                try:
                    db.execute("INSERT INTO users (email) VALUES (?)", (email,))
                    added.append(email)
                except sqlite3.IntegrityError:
                    skipped.append(email)
            db.commit()
            flash(
                f"Added {len(added)} emails. Skipped {len(skipped)} duplicates.",
                "success",
            )
    return redirect(url_for("admin"))


@app.route("/admin/add_user", methods=["POST"])
@admin_required
def admin_add_user():
    db = get_db()
    email = request.form.get("new_user_email", "").strip().lower()
    if email:
        try:
            db.execute("INSERT INTO users (email) VALUES (?)", (email,))
            db.commit()
            flash(f"User {email} added.", "success")
        except sqlite3.IntegrityError:
            flash(f"User {email} already exists.", "warning")
    else:
        flash("No email provided.", "danger")
    return redirect(url_for("admin"))


@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    db = get_db()
    email = request.form.get("delete_user_email", "").strip().lower()
    if email:
        db.execute("DELETE FROM users WHERE email = ?", (email,))
        db.commit()
        flash(f"User {email} deleted.", "success")
    else:
        flash("No email provided.", "danger")
    return redirect(url_for("admin"))


@app.route("/admin/add_reservation", methods=["POST"])
@admin_required
def admin_add_reservation():
    db = get_db()
    email = request.form.get("reservation_email", "").strip().lower()
    meal_slot_id = request.form.get("meal_slot_id", "").strip()
    if not email or not meal_slot_id:
        flash("Email and meal slot are required.", "danger")
        return redirect(url_for("admin"))
    timestamp = datetime.now().isoformat()
    try:
        db.execute(
            "INSERT INTO reservations (user_email, meal_slot_id, timestamp) VALUES (?, ?, ?)",
            (email, meal_slot_id, timestamp),
        )
        db.commit()
        flash(f"Reservation for {email} added to meal slot {meal_slot_id}.", "success")
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
    return (
        "Could not verify your access level for that URL.\n"
        "You have to login with proper credentials",
        401,
        {"WWW-Authenticate": 'Basic realm="Login Required"'},
    )


if __name__ == "__main__":
    app.run(debug=True)
