#!/usr/bin/env python3
import json
from db import get_db
from cookie_util import get_email_from_cookie

def main():
    print("Content-Type: application/json\n")

    email = get_email_from_cookie()
    if not email:
        print(json.dumps({"error": "not_logged_in"}))
        return

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, date, meal_type,
               (SELECT COUNT(*) FROM reservations r WHERE r.meal_slot_id = ms.id) AS current_count,
               capacity
        FROM meal_slots ms
        ORDER BY date, meal_type
    """)
    rows = c.fetchall()
    conn.close()

    slots = []
    for row in rows:
        slot_id, date, meal_type, current_count, capacity = row
        slots.append({
            "id": slot_id,
            "date": date,
            "meal_type": meal_type,
            "current_count": current_count,
            "capacity": capacity
        })

    print(json.dumps({"slots": slots}))

if __name__ == "__main__":
    main()
