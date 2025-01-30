#!/usr/bin/env python3
import cgi
import datetime
from db import get_db
from cookie_util import get_email_from_cookie

print("Content-Type: text/html\n")

def main():
    # Read the user's email from cookie
    email = get_email_from_cookie()
    if not email:
        print("<h1>Error: Not logged in</h1>")
        print("<p><a href=\"/\">Go to Home</a></p>")
        return

    # Parse the form for meal slot IDs
    form = cgi.FieldStorage()
    slot_ids = form.getlist("slot_id")

    conn = get_db()
    c = conn.cursor()

    errors = []
    reserved_count = 0

    for sid in slot_ids:
        # Check capacity
        c.execute("""
            SELECT capacity,
                   (SELECT COUNT(*) FROM reservations WHERE meal_slot_id = ms.id) AS current_count
            FROM meal_slots ms
            WHERE ms.id = ?
        """, (sid,))
        row = c.fetchone()
        if not row:
            errors.append(f"Slot {sid} does not exist.")
            continue

        capacity, current_count = row
        if current_count >= capacity:
            errors.append(f"Slot {sid} is already full.")
            continue

        # Insert reservation
        ts = datetime.datetime.utcnow().isoformat()
        try:
            c.execute("""
                INSERT INTO reservations (user_email, meal_slot_id, timestamp)
                VALUES (?, ?, ?)
            """, (email, sid, ts))
            conn.commit()
            reserved_count += 1
        except:
            errors.append(f"Could not reserve slot {sid} (maybe already reserved?)")

    conn.close()

    if errors:
        print("<h1>Some errors occurred</h1>")
        for e in errors:
            print(f"<p>{e}</p>")
    else:
        print(f"<h1>Success!</h1>")
        print(f"<p>Reserved {reserved_count} slot(s).</p>")

    print('<p><a href="/reservations.html">Back to Reservations</a></p>')

if __name__ == "__main__":
    main()
