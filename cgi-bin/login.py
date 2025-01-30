#!/usr/bin/env python3
import cgi
from db import get_db
from cookie_util import set_email_cookie

print("Content-Type: text/html")

def main():
    form = cgi.FieldStorage()
    email = form.getvalue("email", "").strip().lower()

    # Connect to DB, check if user is in "users"
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT email FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()

    if not row:
        # If user not in DB, show an error
        print("\n")  # End headers
        print("<html><body>")
        print("<h1>User not registered. Please try again.</h1>")
        print("<p><a href=\"/\">Back to Home</a></p>")
        print("</body></html>")
        return

    # Otherwise, set cookie & redirect
    set_email_cookie(email)
    print("Status: 302 Found")
    print("Location: /reservations.html\n")

if __name__ == "__main__":
    main()
