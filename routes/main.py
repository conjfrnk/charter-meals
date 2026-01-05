"""Main user-facing routes."""

import logging
import sqlite3
import threading
from datetime import datetime, date, timedelta

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from zoneinfo import ZoneInfo

from extensions import limiter, cache, csrf
from utils.db import get_db
from utils.helpers import is_pub_slot
from utils.cache import (
    get_meal_slots_data,
    get_slot_counts,
    get_user_reservations,
    get_user_current_meals,
    check_user_has_pub_current,
    get_manual_pub_info,
    get_reservation_settings,
    get_website_content,
)
from routes.auth import login_required

main_bp = Blueprint("main", __name__)

# Slot generation state
last_slot_generation = None
_slot_generation_lock = threading.Lock()


def generate_next_week_meal_slots():
    """Generate meal slots for the upcoming week."""
    global last_slot_generation
    try:
        # Use lock to prevent race conditions when checking/updating last_slot_generation
        # Keep lock held during the entire operation to prevent concurrent slot generation
        with _slot_generation_lock:
            if (
                last_slot_generation
                and (datetime.now() - last_slot_generation).total_seconds() < 21600
            ):
                return

            db = get_db()
            today = date.today()
            next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
            next_sunday = next_monday + timedelta(days=6)
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
                # Only update last_slot_generation after successful commit
                last_slot_generation = datetime.now()
                if slots_created > 0:
                    logging.info(
                        f"Generated {slots_created} new meal slots for week starting {next_monday}"
                    )
                    # Invalidate meal slots cache when new slots are created
                    cache.delete_memoized(get_meal_slots_data, next_monday, next_sunday)
            except Exception as e:
                logging.error(f"Error committing meal slot generation: {e}")
                db.rollback()

    except Exception as e:
        logging.error(f"Error in generate_next_week_meal_slots: {e}")
        # Don't raise the exception - we want the app to continue working


@main_bp.route("/")
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
                raise ValueError(
                    "Missing reservation_open_time or reservation_close_time in settings."
                )
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


@main_bp.route("/reserve", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def reserve():
    if session.get("netid") == "guest":
        flash("Guest users cannot submit reservations.", "danger")
        return redirect(url_for("main.index"))

    # Validate input
    selected_slots_raw = request.form.getlist("meal_slot")
    if not selected_slots_raw:
        flash("No meal slots selected.", "danger")
        return redirect(url_for("main.index"))

    # Validate slot IDs are integers within reasonable bounds
    MAX_SLOT_ID = 10000000
    selected_slots = set()
    for slot_id in selected_slots_raw:
        try:
            slot_id_int = int(slot_id)
            if slot_id_int > 0 and slot_id_int <= MAX_SLOT_ID:
                selected_slots.add(str(slot_id_int))
            elif slot_id_int > MAX_SLOT_ID:
                flash("Invalid meal slot selection.", "danger")
                return redirect(url_for("main.index"))
        except (ValueError, TypeError):
            flash("Invalid meal slot selection.", "danger")
            return redirect(url_for("main.index"))

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
        return redirect(url_for("main.index"))

    # Define current_week_start / current_week_end
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
        return redirect(url_for("main.index"))
    if not manual_pub_exists and len(selected_slots) > total_allowed:
        flash(
            f"You cannot select more than {total_allowed} meal(s) this week.", "danger"
        )
        return redirect(url_for("main.index"))

    pub_count = 0
    for slot_id in selected_slots:
        cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (slot_id,))
        meal_slot = cur.fetchone()
        if meal_slot and is_pub_slot(meal_slot):
            pub_count += 1
    if pub_count > 1:
        flash("You cannot select more than 1 pub night.", "danger")
        return redirect(url_for("main.index"))

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
            flash("Error deleting reservation. Please try again.", "danger")
            return redirect(url_for("main.index"))
    for slot_id in to_add:
        try:
            cur = db.execute("SELECT * FROM meal_slots WHERE id = ?", (slot_id,))
            meal_slot = cur.fetchone()
            if not meal_slot:
                flash("Meal slot not found.", "danger")
                return redirect(url_for("main.index"))
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
                return redirect(url_for("main.index"))
            db.execute(
                "INSERT INTO reservations (netid, meal_slot_id, timestamp) VALUES (?, ?, ?)",
                (user_netid, slot_id, server_timestamp),
            )
        except sqlite3.IntegrityError as e:
            if "full" in str(e).lower():
                flash("The meal slot became full. Please try again.", "danger")
            else:
                logging.error(f"Integrity error adding reservation for slot {slot_id}: {e}")
                flash("Error adding reservation. Please try again.", "danger")
            return redirect(url_for("main.index"))
        except Exception as e:
            logging.error(f"Error adding reservation for slot {slot_id}: {e}")
            flash("Error adding reservation. Please try again.", "danger")
            return redirect(url_for("main.index"))
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error(f"Database commit failed: {e}")
        flash("Error saving reservations. Please try again.", "danger")
        return redirect(url_for("main.index"))
    flash("Reservations updated successfully.", "success")

    # Invalidate caches after reservation changes
    cache.delete_memoized(get_slot_counts, next_monday, next_sunday)
    cache.delete_memoized(get_user_reservations, user_netid, next_monday, next_sunday)
    cache.delete_memoized(
        get_user_current_meals, user_netid, current_week_start, current_week_end
    )
    cache.delete_memoized(get_user_current_meals, user_netid, next_monday, next_sunday)
    cache.delete_memoized(
        check_user_has_pub_current, user_netid, current_week_start, current_week_end
    )
    cache.delete_memoized(get_manual_pub_info, user_netid, next_monday, next_sunday)

    return redirect(url_for("main.index"))


@main_bp.route("/meal_counts")
@login_required
@csrf.exempt  # AJAX GET request doesn't need CSRF protection
@limiter.limit("60 per minute")
def meal_counts():
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)

    # Use the cached function
    counts = get_slot_counts(next_monday, next_sunday)
    return jsonify(counts)
