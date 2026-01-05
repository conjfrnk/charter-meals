"""Cached data access functions."""

import logging
from datetime import datetime

from extensions import cache
from utils.db import get_db
from utils.helpers import is_pub_slot


@cache.memoize(timeout=60)
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


@cache.memoize(timeout=300)
def get_website_content():
    """Get all website content from the database."""
    db = get_db()
    cur = db.execute("SELECT content_key, content_value FROM website_content")
    return {row["content_key"]: row["content_value"] for row in cur.fetchall()}
