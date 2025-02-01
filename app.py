import os
import sqlite3
from datetime import datetime, date, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, jsonify, g, abort, Response
)

app = Flask(__name__)

# Load secret key from secrets.txt
secret_path = os.path.join(os.path.dirname(__file__), 'secrets.txt')
try:
    with open(secret_path, 'r') as f:
        app.secret_key = f.read().strip()
except FileNotFoundError:
    raise RuntimeError("Secret key file not found. Please create a 'secrets.txt' file with a generated secret key.")

# Database location as specified:
app.config['DATABASE'] = '/var/www/data/meals.db'

# ---------------------------
# Database Helpers
# ---------------------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        # Enable foreign keys for SQLite
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.executescript(f.read())
    db.commit()

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    print('Initialized the database.')

# ---------------------------
# Custom Template Filter
# ---------------------------
@app.template_filter('weekday')
def weekday_filter(date_str):
    d = datetime.strptime(date_str, '%Y-%m-%d').date()
    return d.weekday()  # Monday=0, Tuesday=1, ..., Sunday=6

# ---------------------------
# Next Week Meal Slot Generation
# ---------------------------
def generate_next_week_meal_slots():
    """
    Generate meal slots for the next week (Monday to Sunday).
    For weekdays (Mon-Fri): breakfast, lunch, dinner.
    For weekends (Sat-Sun): brunch, dinner.
    """
    db = get_db()
    today = date.today()
    # Calculate next Monday: this week’s Monday + 7 days.
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    days = [next_monday + timedelta(days=i) for i in range(7)]
    for d in days:
        day_str = d.isoformat()
        if d.weekday() < 5:  # Monday to Friday
            meals = ['breakfast', 'lunch', 'dinner']
        else:
            meals = ['brunch', 'dinner']
        for meal in meals:
            cur = db.execute('SELECT id FROM meal_slots WHERE date = ? AND meal_type = ?', (day_str, meal))
            if cur.fetchone() is None:
                db.execute('INSERT INTO meal_slots (date, meal_type, capacity) VALUES (?, ?, ?)', (day_str, meal, 25))
    db.commit()

# ---------------------------
# Helper: Login Required
# ---------------------------
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

# ---------------------------
# Helper: Is This a Pub Slot?
# ---------------------------
def is_pub_slot(meal_slot):
    """
    Returns True if the given meal slot is a pub night.
    For this app, dinner on Tuesday (weekday==1) or Thursday (weekday==3) is a pub night.
    """
    slot_date = datetime.strptime(meal_slot['date'], '%Y-%m-%d').date()
    if meal_slot['meal_type'] == 'dinner' and slot_date.weekday() in [1, 3]:
        return True
    return False

# ---------------------------
# Routes for User Login/Signup
# ---------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        db = get_db()
        cur = db.execute('SELECT email FROM users WHERE email = ?', (email,))
        user = cur.fetchone()
        if user:
            session['user_email'] = email
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email not recognized. Please contact the administrator.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Ensure meal slots exist for next week
    generate_next_week_meal_slots()
    db = get_db()
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    cur = db.execute('SELECT * FROM meal_slots WHERE date BETWEEN ? AND ? ORDER BY date',
                     (next_monday.isoformat(), next_sunday.isoformat()))
    meal_slots = cur.fetchall()

    # Group meal slots by date (so we can list Monday -> Sunday)
    slots_by_date = {}
    for slot in meal_slots:
        slots_by_date.setdefault(slot['date'], []).append(slot)
    
    # Get the user's current reservations for next week
    cur = db.execute('''
        SELECT meal_slot_id FROM reservations r 
        JOIN meal_slots ms ON r.meal_slot_id = ms.id 
        WHERE r.user_email = ? AND ms.date BETWEEN ? AND ?
    ''', (session['user_email'], next_monday.isoformat(), next_sunday.isoformat()))
    user_reservations = {row['meal_slot_id'] for row in cur.fetchall()}
    
    return render_template('index.html', slots_by_date=slots_by_date, user_reservations=user_reservations)

@app.route('/reserve', methods=['POST'])
@login_required
def reserve():
    selected_slots = request.form.getlist('meal_slot')
    client_timestamp = request.form.get('client_timestamp')
    if not client_timestamp:
        flash('Client timestamp missing.', 'danger')
        return redirect(url_for('index'))
    try:
        timestamp = datetime.fromisoformat(client_timestamp)
    except ValueError:
        flash('Invalid timestamp format.', 'danger')
        return redirect(url_for('index'))
    
    db = get_db()
    user_email = session['user_email']
    
    # --- Business Rule Checks (server–side) ---
    # Rule 1: Only 2 non-pub meals per week.
    # Rule 2: Only 1 pub night (Tuesday/Thursday dinner) every 2 weeks.
    
    today = date.today()
    next_monday = today - timedelta(days=today.weekday()) + timedelta(days=7)
    next_sunday = next_monday + timedelta(days=6)
    
    # Count non-pub reservations for next week
    cur = db.execute('''
        SELECT r.*, ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.user_email = ? AND ms.date BETWEEN ? AND ?
    ''', (user_email, next_monday.isoformat(), next_sunday.isoformat()))
    weekly_reservations = cur.fetchall()
    non_pub_count = sum(
        1 for res in weekly_reservations
        if not (res['meal_type'] == 'dinner' and datetime.strptime(res['date'], '%Y-%m-%d').date().weekday() in [1, 3])
    )
    
    # Check for an existing pub night in the last 2 weeks (including future reservations)
    two_weeks_ago = today - timedelta(weeks=2)
    cur = db.execute('''
        SELECT r.*, ms.date, ms.meal_type FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        WHERE r.user_email = ? AND ms.date >= ?
    ''', (user_email, two_weeks_ago.isoformat()))
    recent_reservations = cur.fetchall()
    pub_exists = any(
        (res['meal_type'] == 'dinner' and datetime.strptime(res['date'], '%Y-%m-%d').date().weekday() in [1, 3])
        for res in recent_reservations
    )
    
    error_occurred = False
    for slot_id in selected_slots:
        cur = db.execute('SELECT * FROM meal_slots WHERE id = ?', (slot_id,))
        meal_slot = cur.fetchone()
        if not meal_slot:
            flash('Meal slot not found.', 'danger')
            error_occurred = True
            continue

        # Check if this meal slot is already full
        cur = db.execute('SELECT COUNT(*) as count FROM reservations WHERE meal_slot_id = ?', (slot_id,))
        count = cur.fetchone()['count']
        if count >= meal_slot['capacity']:
            flash(f"{meal_slot['meal_type'].capitalize()} on {meal_slot['date']} is already full.", 'danger')
            error_occurred = True
            continue

        # Check the user’s reservation limits
        if is_pub_slot(meal_slot):
            if pub_exists:
                flash('You have already reserved a pub night in the last 2 weeks.', 'danger')
                error_occurred = True
                continue
            pub_exists = True  # mark that a pub reservation is now being made
        else:
            if non_pub_count >= 2:
                flash('You have already reserved 2 meals this week.', 'danger')
                error_occurred = True
                continue
            non_pub_count += 1

        try:
            db.execute(
                'INSERT INTO reservations (user_email, meal_slot_id, timestamp) VALUES (?, ?, ?)',
                (user_email, slot_id, client_timestamp)
            )
            db.commit()
            flash(f"Reserved {meal_slot['meal_type']} on {meal_slot['date']}.", 'success')
        except sqlite3.IntegrityError:
            flash(f"You have already reserved {meal_slot['meal_type']} on {meal_slot['date']}.", 'warning')

    if error_occurred:
        return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/meal_counts')
def meal_counts():
    """Return JSON with the reservation counts per meal slot."""
    db = get_db()
    cur = db.execute('SELECT meal_slot_id, COUNT(*) as count FROM reservations GROUP BY meal_slot_id')
    counts = {str(row['meal_slot_id']): row['count'] for row in cur.fetchall()}
    return jsonify(counts)

# ---------------------------
# Admin Routes and Endpoints
# ---------------------------
def check_admin_auth(username, password):
    return username == 'admin' and password == 'admin'

def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        auth = request.authorization
        if not auth or not check_admin_auth(auth.username, auth.password):
            return abort(401)
        return view(**kwargs)
    return wrapped_view

@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    db = get_db()
    # Get known users
    cur = db.execute('SELECT email FROM users ORDER BY email')
    users = cur.fetchall()

    # Get reservations grouped by meal slot
    cur = db.execute('''
        SELECT r.id as reservation_id, r.user_email, ms.id as meal_slot_id, ms.date, ms.meal_type, r.timestamp
        FROM reservations r
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        ORDER BY ms.date, ms.meal_type
    ''')
    reservations = cur.fetchall()
    # Group reservations by meal slot (keyed by "date - meal_type")
    reservations_by_slot = {}
    for res in reservations:
        key = f"{res['date']} - {res['meal_type']}"
        if key not in reservations_by_slot:
            reservations_by_slot[key] = {
                'meal_slot_id': res['meal_slot_id'],
                'date': res['date'],
                'meal_type': res['meal_type'],
                'reservations': []
            }
        reservations_by_slot[key]['reservations'].append(res)
    
    return render_template('admin.html', users=users, reservations_by_slot=reservations_by_slot)

@app.route('/admin/upload_emails', methods=['POST'])
@admin_required
def admin_upload_emails():
    db = get_db()
    if 'emails_file' in request.files:
        f = request.files['emails_file']
        if f:
            try:
                content = f.read().decode('utf-8')
            except Exception as e:
                flash('Error reading file.', 'danger')
                return redirect(url_for('admin'))
            # Split on newlines and commas
            lines = content.replace(',', '\n').splitlines()
            emails = [line.strip().lower() for line in lines if line.strip()]
            added = []
            skipped = []
            for email in emails:
                try:
                    db.execute('INSERT INTO users (email) VALUES (?)', (email,))
                    added.append(email)
                except sqlite3.IntegrityError:
                    skipped.append(email)
            db.commit()
            flash(f"Added {len(added)} emails. Skipped {len(skipped)} duplicates.", "success")
    return redirect(url_for('admin'))

@app.route('/admin/add_user', methods=['POST'])
@admin_required
def admin_add_user():
    db = get_db()
    email = request.form.get('new_user_email', '').strip().lower()
    if email:
        try:
            db.execute('INSERT INTO users (email) VALUES (?)', (email,))
            db.commit()
            flash(f"User {email} added.", "success")
        except sqlite3.IntegrityError:
            flash(f"User {email} already exists.", "warning")
    else:
        flash("No email provided.", "danger")
    return redirect(url_for('admin'))

@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    db = get_db()
    email = request.form.get('delete_user_email', '').strip().lower()
    if email:
        db.execute('DELETE FROM users WHERE email = ?', (email,))
        db.commit()
        flash(f"User {email} deleted.", "success")
    else:
        flash("No email provided.", "danger")
    return redirect(url_for('admin'))

@app.route('/admin/add_reservation', methods=['POST'])
@admin_required
def admin_add_reservation():
    db = get_db()
    email = request.form.get('reservation_email', '').strip().lower()
    meal_slot_id = request.form.get('meal_slot_id', '').strip()
    if not email or not meal_slot_id:
        flash("Email and meal slot are required.", "danger")
        return redirect(url_for('admin'))
    # Use the current timestamp
    timestamp = datetime.now().isoformat()
    try:
        db.execute('INSERT INTO reservations (user_email, meal_slot_id, timestamp) VALUES (?, ?, ?)', 
                   (email, meal_slot_id, timestamp))
        db.commit()
        flash(f"Reservation for {email} added to meal slot {meal_slot_id}.", "success")
    except sqlite3.IntegrityError:
        flash("Reservation already exists or error occurred.", "warning")
    return redirect(url_for('admin'))

@app.route('/admin/delete_reservation/<int:reservation_id>', methods=['POST'])
@admin_required
def admin_delete_reservation(reservation_id):
    db = get_db()
    db.execute('DELETE FROM reservations WHERE id = ?', (reservation_id,))
    db.commit()
    flash("Reservation deleted.", "success")
    return redirect(url_for('admin'))

@app.route('/admin/download_meal_signups')
@admin_required
def admin_download_meal_signups():
    db = get_db()
    cur = db.execute('''
        SELECT ms.date, ms.meal_type, r.user_email 
        FROM reservations r 
        JOIN meal_slots ms ON r.meal_slot_id = ms.id
        ORDER BY ms.date, ms.meal_type
    ''')
    rows = cur.fetchall()
    output = []
    current_meal = None
    for row in rows:
        meal = f"{row['date']} - {row['meal_type']}"
        netid = row['user_email'].split('@')[0]
        if current_meal != meal:
            output.append(f"\nMeal: {meal}\n")
            current_meal = meal
        output.append(netid)
    csv_content = "\n".join(output)
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=meal_signups.csv"}
    )

@app.errorhandler(401)
def unauthorized(error):
    return ('Could not verify your access level for that URL.\n'
            'You have to login with proper credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Login Required"'})

if __name__ == '__main__':
    app.run(debug=True)
