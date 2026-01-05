"""Admin routes and functionality."""

import os
import re
import csv
import io
import logging
import sqlite3
import shutil
import tempfile
from datetime import datetime, date, timedelta

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    Response,
    current_app,
)
from werkzeug.security import generate_password_hash, check_password_hash
from zoneinfo import ZoneInfo

from extensions import limiter, cache
from utils.db import get_db
from utils.helpers import is_pub_slot, validate_csv_upload, parse_markdown, export_sort_key
from utils.cache import (
    get_slot_counts,
    get_user_reservations,
    get_user_current_meals,
    check_user_has_pub_current,
    get_manual_pub_info,
    get_reservation_settings,
    get_website_content,
)
from routes.auth import admin_required

admin_bp = Blueprint("admin", __name__)


# ---------------------------
# Admin Dashboard
# ---------------------------
@admin_bp.route("/", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    db = get_db()

    # Handle POST requests for content management
    if request.method == "POST":
        updated_count = 0
        content_keys = [
            "welcome_header",
            "welcome_message",
            "contact_info",
            "meal_rules_title",
            "meal_rules",
            "feedback_link",
            "feedback_text",
        ]
        for key in content_keys:
            if key == "meal_rules":
                # Try to get the list of rules from the form
                rules_list = request.form.getlist("content_value_meal_rules_list[]")
                if rules_list:
                    # Remove empty rules, strip whitespace, and limit to 50 rules max
                    rules_list = [r.strip()[:500] for r in rules_list[:50] if r.strip()]
                    content_value = "\n".join(rules_list)
                else:
                    # Fallback to textarea with length limit
                    content_value = request.form.get(f"content_value_{key}", "").strip()[:10000]
            else:
                # Limit content length to prevent DoS
                content_value = request.form.get(f"content_value_{key}", "").strip()[:5000]
            if content_value:
                try:
                    html_content = parse_markdown(content_value, key)
                    db.execute(
                        "INSERT OR REPLACE INTO website_content (content_key, content_value, last_updated) VALUES (?, ?, CURRENT_TIMESTAMP)",
                        (key, html_content),
                    )
                    updated_count += 1
                except Exception as e:
                    logging.error(f"Error updating content '{key}': {e}")
                    flash("Error updating content. Please try again.", "danger")
        if updated_count > 0:
            db.commit()
            cache.delete_memoized(get_website_content)
            flash(f"Successfully updated {updated_count} content items.", "success")
        else:
            flash("No content was updated.", "warning")
        return redirect(url_for("admin.admin_dashboard"))

    # Fetch users and attach their reservations for current & next week
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
            - timedelta(days=datetime.strptime(row["date"], "%Y-%m-%d").date().weekday())
            for row in cur.fetchall()
        },
        reverse=True,
    )
    cur = db.execute("SELECT username FROM admins ORDER BY username")
    admin_accounts = [row["username"] for row in cur.fetchall()]
    is_super_admin = session.get("admin_username") == "admin"
    is_admin = session.get("admin_username") is not None

    # For Reservations subtabs: next week's meal slots grouped by weekday
    cur = db.execute(
        "SELECT * FROM meal_slots WHERE date BETWEEN ? AND ? ORDER BY date",
        (next_monday.isoformat(), next_sunday.isoformat()),
    )
    week_meal_slots = cur.fetchall()
    weekly_slots = {i: [] for i in range(7)}
    for slot in week_meal_slots:
        d = datetime.strptime(slot["date"], "%Y-%m-%d").date()
        weekly_slots[d.weekday()].append(slot)
    # Sort each day's slots by meal order
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
        content = row["content_value"]
        content_key = row["content_key"]

        if content_key == "meal_rules":
            content = content.replace("<ul>", "").replace("</ul>", "")
            rules = re.findall(r"<li>(.*?)</li>", content, flags=re.DOTALL)
            meal_rules_list = [rule.strip() for rule in rules if rule.strip()]
            content = "\n".join(meal_rules_list)
        else:
            content = re.sub(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', r"[\2](\1)", content)
            content = re.sub(r"<strong>([^<]+)</strong>", r"**\1**", content)
            content = re.sub(r"<em>([^<]+)</em>", r"*\1*", content)
            content = content.replace("<br>", "\n")

        content_items[content_key] = content
    content_items["meal_rules_list"] = meal_rules_list

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


# ---------------------------
# Admin Settings
# ---------------------------
@admin_bp.route("/settings", methods=["POST"])
@admin_required
@limiter.limit("20 per minute")
def admin_settings():
    db = get_db()
    manual_status = request.form.get("manual_status", "auto").strip()
    open_day = request.form.get("reservation_open_day", "").strip()
    open_time = request.form.get("reservation_open_time", "").strip()
    close_day = request.form.get("reservation_close_day", "").strip()
    close_time = request.form.get("reservation_close_time", "").strip()

    # Validate inputs
    valid_statuses = ["auto", "open", "closed"]
    valid_days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    time_pattern = re.compile(r"^([01]?[0-9]|2[0-3]):[0-5][0-9]$")

    if manual_status not in valid_statuses:
        flash("Invalid reservation status.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if open_day and open_day not in valid_days:
        flash("Invalid open day.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if close_day and close_day not in valid_days:
        flash("Invalid close day.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if open_time and not time_pattern.match(open_time):
        flash("Invalid open time format. Use HH:MM.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if close_time and not time_pattern.match(close_time):
        flash("Invalid close time format. Use HH:MM.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

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
    cache.delete_memoized(get_reservation_settings)
    flash("Settings updated.", "success")
    return redirect(url_for("admin.admin_dashboard"))


# ---------------------------
# Admin Password Management
# ---------------------------
@admin_bp.route("/change_password", methods=["GET", "POST"])
@admin_required
def admin_change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new_pass = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not current or not new_pass or not confirm:
            flash("All password fields are required.", "danger")
            return redirect(url_for("admin.admin_change_password"))

        if len(new_pass) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return redirect(url_for("admin.admin_change_password"))

        if len(new_pass) > 100:
            flash("Password is too long.", "danger")
            return redirect(url_for("admin.admin_change_password"))

        if new_pass != confirm:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("admin.admin_change_password"))

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
            return redirect(url_for("admin.admin_dashboard"))
        else:
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("admin.admin_change_password"))
    return render_template("admin_change_password.html")


@admin_bp.route("/add_admin", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def admin_add_admin():
    username = request.form.get("new_admin_username", "").strip()
    password = request.form.get("new_admin_password", "").strip()

    if not username or not password:
        flash("Username and password are required for new admin.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if len(username) > 50 or not re.match(r"^[a-zA-Z0-9_-]+$", username):
        flash("Invalid username format. Use only letters, numbers, underscores, and hyphens.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if len(password) > 100:
        flash("Password is too long.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    db = get_db()
    try:
        password_hash = generate_password_hash(password, method="pbkdf2:sha256")
        db.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' created new admin account '{username}'"
        )
        flash("Admin account created successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Admin account already exists.", "warning")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/delete_admin/<username>", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def admin_delete_admin(username):
    if not username or len(username) > 50 or not re.match(r"^[a-zA-Z0-9_-]+$", username):
        flash("Invalid username format.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if session.get("admin_username") != "admin":
        flash("You do not have permission to delete admin accounts.", "danger")
        return redirect(url_for("admin.admin_dashboard"))
    if username == "admin":
        flash("Cannot delete the primary admin account.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    db = get_db()
    cur = db.execute("SELECT username FROM admins WHERE username = ?", (username,))
    if not cur.fetchone():
        flash("Admin account not found.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    db.execute("DELETE FROM admins WHERE username = ?", (username,))
    db.commit()
    logging.info(
        f"Security: Admin '{session.get('admin_username', 'unknown')}' deleted admin account '{username}'"
    )
    flash("Admin account deleted.", "success")
    return redirect(url_for("admin.admin_dashboard"))


# ---------------------------
# User Management
# ---------------------------
@admin_bp.route("/upload_emails", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def admin_upload_emails():
    MAX_FILE_SIZE = 1 * 1024 * 1024

    db = get_db()
    if "emails_file" in request.files:
        f = request.files["emails_file"]

        is_valid, error_msg = validate_csv_upload(f)
        if not is_valid and error_msg:
            flash(error_msg, "danger")
            return redirect(url_for("admin.admin_dashboard"))

        if f:
            try:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                if file_size > MAX_FILE_SIZE:
                    flash("File too large. Maximum size is 1MB.", "danger")
                    return redirect(url_for("admin.admin_dashboard"))

                content = f.read().decode("utf-8")
            except UnicodeDecodeError:
                flash("Error reading file: Invalid file encoding. Please use UTF-8.", "danger")
                return redirect(url_for("admin.admin_dashboard"))
            except Exception as e:
                logging.error(f"Error reading upload file: {e}")
                flash("Error reading file.", "danger")
                return redirect(url_for("admin.admin_dashboard"))

            f_io = io.StringIO(content)
            reader = csv.reader(f_io)
            added = []
            updated = []
            skipped = []
            invalid = []
            row_count = 0

            for row in reader:
                row_count += 1
                if row_count > 2000:
                    flash("File contains too many rows. Only first 2000 rows processed.", "warning")
                    break

                if len(row) < 2:
                    continue
                netid = row[0].strip().lower()
                name = row[1].strip()
                if not netid:
                    continue
                if len(netid) > 20 or not re.match(r"^[a-zA-Z0-9_-]+$", netid):
                    invalid.append(netid[:20])
                    continue
                name = re.sub(r'[<>"\']', "", name)
                if len(name) > 100:
                    name = name[:100]
                cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
                existing = cur.fetchone()
                try:
                    if existing:
                        db.execute("UPDATE users SET name = ? WHERE netid = ?", (name, netid))
                        updated.append(netid)
                    else:
                        db.execute("INSERT INTO users (netid, name) VALUES (?, ?)", (netid, name))
                        added.append(netid)
                except sqlite3.IntegrityError:
                    skipped.append(netid)
            db.commit()

            logging.info(
                f"Security: Admin '{session.get('admin_username', 'unknown')}' uploaded users - added: {len(added)}, updated: {len(updated)}"
            )

            msg = f"Added: {len(added)}. Updated: {len(updated)}. Skipped: {len(skipped)}."
            if invalid:
                msg += f" Invalid format: {len(invalid)}."
            flash(msg, "success")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/add_user", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def admin_add_user():
    db = get_db()
    netids_str = request.form.get("new_netid", "")

    valid_netids = []
    invalid_netids = []
    for netid in netids_str.split(","):
        netid = netid.strip().lower()
        if netid:
            if len(netid) <= 20 and re.match(r"^[a-zA-Z0-9_-]+$", netid):
                valid_netids.append(netid)
            else:
                invalid_netids.append(netid)

    if not valid_netids:
        if invalid_netids:
            flash(f"Invalid NetID format: {len(invalid_netids)} netid(s) skipped.", "danger")
        else:
            flash("No netid provided.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    added = []
    skipped = []
    for netid in valid_netids:
        try:
            db.execute("INSERT INTO users (netid) VALUES (?)", (netid,))
            added.append(netid)
        except sqlite3.IntegrityError:
            skipped.append(netid)
    db.commit()

    msg = f"Added {len(added)} user(s)." if added else "No users added."
    if skipped:
        msg += f" Skipped {len(skipped)} (already exist)."
    if invalid_netids:
        msg += f" Invalid format: {len(invalid_netids)}."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/delete_user", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def admin_delete_user():
    db = get_db()
    netids_str = request.form.get("delete_netid", "")

    if len(netids_str) > 10000:
        flash("Input too long. Please delete users in smaller batches.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    netids = [x.strip().lower() for x in netids_str.split(",") if x.strip()]

    if len(netids) > 100:
        flash("Too many netids. Please delete users in smaller batches (max 100).", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    if not netids:
        flash("No netid provided.", "danger")
        return redirect(url_for("admin.admin_dashboard"))
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
    flash(f"Deleted {len(deleted)} user(s). Not found: {len(not_found)}.", "success")
    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/bulk_delete_users", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def admin_bulk_delete_users():
    MAX_FILE_SIZE = 1 * 1024 * 1024

    db = get_db()
    if "delete_netids_file" in request.files:
        f = request.files["delete_netids_file"]

        is_valid, error_msg = validate_csv_upload(f)
        if not is_valid and error_msg:
            flash(error_msg, "danger")
            return redirect(url_for("admin.admin_dashboard"))

        if f:
            try:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                if file_size > MAX_FILE_SIZE:
                    flash("File too large. Maximum size is 1MB.", "danger")
                    return redirect(url_for("admin.admin_dashboard"))

                content = f.read().decode("utf-8")
            except UnicodeDecodeError:
                flash("Error reading file: Invalid file encoding. Please use UTF-8.", "danger")
                return redirect(url_for("admin.admin_dashboard"))
            except Exception as e:
                logging.error(f"Error reading bulk delete file: {e}")
                flash("Error reading file.", "danger")
                return redirect(url_for("admin.admin_dashboard"))

            netid_candidates = re.split(r"[\n,]+", content)
            valid_netids = []
            invalid_netids = []

            for netid in netid_candidates:
                netid = netid.strip().lower()
                if netid:
                    if len(netid) <= 20 and re.match(r"^[a-zA-Z0-9_-]+$", netid):
                        valid_netids.append(netid)
                    else:
                        invalid_netids.append(netid[:20])

            if len(valid_netids) > 1000:
                flash("Too many netIDs in file. Maximum is 1000 per request.", "danger")
                return redirect(url_for("admin.admin_dashboard"))

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

            logging.info(
                f"Security: Admin '{session.get('admin_username', 'unknown')}' bulk deleted {len(removed)} users"
            )

            msg = f"Bulk deletion complete: {len(removed)} netIDs removed, {len(not_found)} netIDs not found."
            if invalid_netids:
                msg += f" {len(invalid_netids)} invalid format netIDs skipped."
            flash(msg, "success")
        else:
            flash("No file selected.", "danger")
    else:
        flash("No file uploaded.", "danger")
    return redirect(url_for("admin.admin_dashboard"))


# ---------------------------
# Reservation Management
# ---------------------------
@admin_bp.route("/add_reservation", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def admin_add_reservation():
    try:
        db = get_db()
        netids_str = request.form.get("reservation_netid", "")
        meal_slot_id = request.form.get("meal_slot_id", "").strip()

        if not meal_slot_id:
            flash("Meal slot ID is required.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        MAX_SLOT_ID = 10000000
        try:
            meal_slot_id_int = int(meal_slot_id)
            if meal_slot_id_int <= 0 or meal_slot_id_int > MAX_SLOT_ID:
                raise ValueError("Invalid meal slot ID")
        except (ValueError, TypeError):
            flash("Invalid meal slot ID.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        netids = []
        for netid in netids_str.split(","):
            netid = netid.strip().lower()
            if netid and len(netid) <= 20 and re.match(r"^[a-zA-Z0-9_-]+$", netid):
                netids.append(netid)

        if not netids:
            flash("No valid NetIDs provided.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        cur = db.execute("SELECT id, date FROM meal_slots WHERE id = ?", (meal_slot_id_int,))
        slot_info = cur.fetchone()
        if not slot_info:
            flash("Meal slot not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        added = []
        skipped = []
        not_found = []
        server_timestamp = datetime.now(ZoneInfo("America/New_York")).isoformat()

        for netid in netids:
            cur = db.execute("SELECT netid FROM users WHERE netid = ?", (netid,))
            if cur.fetchone() is None:
                not_found.append(netid)
                continue
            try:
                db.execute(
                    "INSERT INTO reservations (netid, meal_slot_id, timestamp, added_by) VALUES (?, ?, ?, ?)",
                    (netid, meal_slot_id_int, server_timestamp, session["admin_username"]),
                )
                added.append(netid)
            except sqlite3.IntegrityError:
                skipped.append(netid)

        db.commit()

        # Invalidate caches
        slot_date = datetime.strptime(slot_info["date"], "%Y-%m-%d").date()
        week_start = slot_date - timedelta(days=slot_date.weekday())
        week_end = week_start + timedelta(days=6)
        cache.delete_memoized(get_slot_counts, week_start, week_end)
        for netid in added:
            cache.delete_memoized(get_user_reservations, netid, week_start, week_end)
            cache.delete_memoized(get_user_current_meals, netid, week_start, week_end)
            cache.delete_memoized(check_user_has_pub_current, netid, week_start, week_end)
            cache.delete_memoized(get_manual_pub_info, netid, week_start, week_end)

        msg = f"Added {len(added)} reservation(s)."
        if skipped:
            msg += f" Skipped {len(skipped)} (already exist)."
        if not_found:
            msg += f" User not found: {len(not_found)}."
        flash(msg, "success" if added else "warning")

    except Exception as e:
        logging.error(f"Error adding reservation: {e}")
        flash("An error occurred while adding reservations.", "danger")

    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/delete_reservation/<int:reservation_id>", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def admin_delete_reservation(reservation_id):
    MAX_RESERVATION_ID = 10000000
    if reservation_id <= 0 or reservation_id > MAX_RESERVATION_ID:
        flash("Invalid reservation ID.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    try:
        db = get_db()

        cur = db.execute(
            "SELECT id, netid, meal_slot_id FROM reservations WHERE id = ?", (reservation_id,)
        )
        reservation = cur.fetchone()
        if not reservation:
            flash("Reservation not found.", "danger")
            return redirect(url_for("admin.admin_dashboard"))

        cur = db.execute("SELECT date FROM meal_slots WHERE id = ?", (reservation["meal_slot_id"],))
        slot_info = cur.fetchone()

        db.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))
        db.commit()

        if slot_info:
            slot_date = datetime.strptime(slot_info["date"], "%Y-%m-%d").date()
            week_start = slot_date - timedelta(days=slot_date.weekday())
            week_end = week_start + timedelta(days=6)
            cache.delete_memoized(get_slot_counts, week_start, week_end)
            cache.delete_memoized(get_user_reservations, reservation["netid"], week_start, week_end)
            cache.delete_memoized(get_user_current_meals, reservation["netid"], week_start, week_end)
            cache.delete_memoized(check_user_has_pub_current, reservation["netid"], week_start, week_end)
            cache.delete_memoized(get_manual_pub_info, reservation["netid"], week_start, week_end)

        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' deleted reservation {reservation_id} for user '{reservation['netid']}'"
        )
        flash("Reservation deleted.", "success")

    except Exception as e:
        logging.error(f"Error deleting reservation {reservation_id}: {e}")
        flash("An error occurred while deleting the reservation.", "danger")

    return redirect(url_for("admin.admin_dashboard"))


# ---------------------------
# Export Functionality
# ---------------------------
@admin_bp.route("/download_meal_signups/<week_start>")
@admin_required
@limiter.limit("30 per minute")
def admin_download_meal_signups_week(week_start):
    try:
        week_start_date = datetime.strptime(week_start, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    db = get_db()
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
    safe_filename = f"meal_signups_{week_start_date.strftime('%Y-%m-%d')}.csv"
    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response


@admin_bp.route("/download_all_meal_signups")
@admin_required
@limiter.limit("10 per minute")
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
    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = 'attachment; filename="meal_signups_all.csv"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response


# ---------------------------
# Content Management
# ---------------------------
@admin_bp.route("/delete_content/<content_key>", methods=["POST"])
@admin_required
@limiter.limit("10 per minute")
def admin_delete_content(content_key):
    allowed_keys = [
        "welcome_header",
        "welcome_message",
        "contact_info",
        "meal_rules_title",
        "meal_rules",
        "feedback_link",
        "feedback_text",
    ]
    if content_key not in allowed_keys:
        flash("Invalid content key.", "danger")
        return redirect(url_for("admin.admin_dashboard"))

    db = get_db()
    try:
        db.execute("DELETE FROM website_content WHERE content_key = ?", (content_key,))
        db.commit()
        cache.delete_memoized(get_website_content)
        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' deleted content '{content_key}'"
        )
        flash("Content deleted successfully.", "success")
    except Exception as e:
        logging.error(f"Error deleting content {content_key}: {e}")
        flash("An error occurred while deleting content.", "danger")
    return redirect(url_for("admin.admin_dashboard"))


# ---------------------------
# Purge and Archive
# ---------------------------
@admin_bp.route("/purge", methods=["POST"])
@admin_required
@limiter.limit("1 per minute")
def admin_purge():
    import routes.main as main_module

    db = get_db()
    try:
        # Create archive tables
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS archived_users (
                netid TEXT PRIMARY KEY,
                name TEXT,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS archived_meal_slots (
                id INTEGER PRIMARY KEY,
                date TEXT NOT NULL,
                meal_type TEXT NOT NULL,
                capacity INTEGER NOT NULL DEFAULT 25,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS archived_reservations (
                id INTEGER PRIMARY KEY,
                netid TEXT NOT NULL,
                meal_slot_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                added_by TEXT,
                archived_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Archive data
        db.execute(
            """
            INSERT INTO archived_users (netid, name)
            SELECT netid, name FROM users
        """
        )

        db.execute(
            """
            INSERT INTO archived_meal_slots (id, date, meal_type, capacity)
            SELECT id, date, meal_type, capacity FROM meal_slots
        """
        )

        db.execute(
            """
            INSERT INTO archived_reservations (id, netid, meal_slot_id, timestamp, added_by)
            SELECT id, netid, meal_slot_id, timestamp, added_by FROM reservations
        """
        )

        # Delete data
        db.execute("DELETE FROM users")
        db.execute("DELETE FROM reservations")
        db.execute("DELETE FROM meal_slots")

        cache.clear()
        
        # Reset slot generation timestamp to allow new slots to be generated
        main_module.last_slot_generation = None

        db.commit()
        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' performed database purge"
        )
        flash(
            "All users, reservations, and meal slots have been archived and purged.",
            "success",
        )
    except Exception as e:
        logging.error(f"Purge failed: {e}")
        flash("Error during purge. Please try again.", "danger")

    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/download_archive")
@admin_required
@limiter.limit("10 per minute")
def admin_download_archive():
    db = get_db()

    try:
        cur = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='archived_users'"
        )
        if not cur.fetchone():
            flash("No archived data found. Run a purge first to create archives.", "warning")
            return redirect(url_for("admin.admin_dashboard"))

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Charter Meals Archive"])
        writer.writerow(["Generated on:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow([])

        writer.writerow(["ARCHIVED USERS"])
        writer.writerow(["NetID", "Name", "Archived At"])
        cur = db.execute("SELECT netid, name, archived_at FROM archived_users ORDER BY netid")
        for row in cur.fetchall():
            writer.writerow([row["netid"], row["name"], row["archived_at"]])
        writer.writerow([])

        writer.writerow(["ARCHIVED MEAL SLOTS"])
        writer.writerow(["ID", "Date", "Meal Type", "Capacity", "Archived At"])
        cur = db.execute(
            "SELECT id, date, meal_type, capacity, archived_at FROM archived_meal_slots ORDER BY date, meal_type"
        )
        for row in cur.fetchall():
            writer.writerow([row["id"], row["date"], row["meal_type"], row["capacity"], row["archived_at"]])
        writer.writerow([])

        writer.writerow(["ARCHIVED RESERVATIONS"])
        writer.writerow(["ID", "NetID", "Meal Slot ID", "Timestamp", "Added By", "Archived At"])
        cur = db.execute(
            "SELECT id, netid, meal_slot_id, timestamp, added_by, archived_at FROM archived_reservations ORDER BY timestamp"
        )
        for row in cur.fetchall():
            writer.writerow(
                [row["id"], row["netid"], row["meal_slot_id"], row["timestamp"], row["added_by"], row["archived_at"]]
            )

        csv_data = output.getvalue()
        output.close()

        safe_filename = f'charter_meals_archive_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        response = Response(csv_data, mimetype="text/csv")
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"

        return response

    except Exception as e:
        logging.error(f"Error generating archive: {e}")
        flash("Error generating archive. Please try again.", "danger")
        return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/clear_archive", methods=["POST"])
@admin_required
@limiter.limit("5 per minute")
def admin_clear_archive():
    db = get_db()
    try:
        db.execute("DELETE FROM archived_users")
        db.execute("DELETE FROM archived_meal_slots")
        db.execute("DELETE FROM archived_reservations")
        db.commit()
        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' cleared all archived data"
        )
        flash("All archived data has been cleared.", "success")
    except Exception as e:
        logging.error(f"Error clearing archive: {e}")
        flash("Error clearing archive. Please try again.", "danger")

    return redirect(url_for("admin.admin_dashboard"))


@admin_bp.route("/backup_database")
@admin_required
@limiter.limit("5 per minute")
def admin_backup_database():
    backup_filename = None
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        display_filename = f"charter_meals_backup_{timestamp}.db"

        fd, backup_filename = tempfile.mkstemp(suffix=".db", prefix="charter_backup_")
        os.close(fd)

        shutil.copy2(current_app.config["DATABASE"], backup_filename)

        with open(backup_filename, "rb") as f:
            data = f.read()

        response = Response(data, mimetype="application/octet-stream")
        response.headers["Content-Disposition"] = f'attachment; filename="{display_filename}"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"

        logging.info(
            f"Security: Admin '{session.get('admin_username', 'unknown')}' downloaded database backup"
        )
        return response

    except Exception as e:
        logging.error(f"Database backup failed: {e}")
        flash("An error occurred while creating backup.", "danger")
        return redirect(url_for("admin.admin_dashboard"))
    finally:
        if backup_filename and os.path.exists(backup_filename):
            try:
                os.remove(backup_filename)
            except OSError as e:
                logging.warning(f"Failed to remove temporary backup file: {e}")
