# Onboarding Guide

Quick-start guide for developers and AI agents working on Charter Meals.

## Quick Start (5 minutes)

```bash
# 1. Setup environment
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Create secret key (min 32 chars)
python -c "import secrets; print(secrets.token_urlsafe(32))" > secrets.txt

# 3. Start Redis (required)
redis-server &  # or: brew services start redis (macOS)

# 4. Initialize and run
flask init-db
flask run
```

Default admin: `admin` / `admin` (change immediately at `/admin/login`)

## Project Overview

**Charter Meals** is a Flask web app for Princeton Charter Club meal sign-ups.

| Layer | Technology |
|-------|------------|
| Backend | Python 3.9+, Flask 2.3+ |
| Database | SQLite (parameterized queries only) |
| Cache/Rate Limiting | Redis + Flask-Caching + Flask-Limiter |
| Frontend | Jinja2, Vanilla JS, CSS3 |
| Production | Gunicorn (OpenBSD with rc.d scripts) |

## File Structure

```
charter-meals/
├── app.py              # Entry point, CLI commands, filters, error handlers
├── config.py           # Configuration (secret key, DB path, CSP)
├── extensions.py       # Flask extensions init
├── routes/
│   ├── auth.py         # Login/logout (POST-only), decorators
│   ├── admin.py        # Admin dashboard routes
│   └── main.py         # User-facing routes (index, reserve, /health)
├── utils/
│   ├── db.py           # get_db(), init_db(), migrations
│   ├── cache.py        # Cached data functions
│   └── helpers.py      # Validation, parsing utilities
├── static/             # main.js, style.css, pcc_logo.png
├── templates/          # Jinja2 templates
├── schema.sql          # Database schema with triggers
├── rc.d/               # OpenBSD init scripts (gunicorn_charter)
├── secrets.txt         # Secret key (gitignored)
└── VERSION             # Version for cache busting
```

## Key Patterns

### Route Pattern
```python
@bp.route("/path", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # sensitive routes
@login_required  # or @admin_required
def route_name():
    if request.method == "POST":
        value = request.form.get("field", "").strip()
        if not value:
            flash("Field required.", "danger")
            return redirect(url_for("blueprint.route_name"))
        try:
            db = get_db()
            db.execute("INSERT INTO t (col) VALUES (?)", (value,))
            db.commit()
            flash("Success.", "success")
        except Exception as e:
            logging.error(f"Error: {e}")
            flash("An error occurred.", "danger")
        return redirect(url_for("blueprint.route_name"))
    return render_template("template.html")
```

### Database Access
```python
db = get_db()
cur = db.execute("SELECT * FROM users WHERE netid = ?", (netid,))
user = cur.fetchone()  # Dict-like: user["name"]
```

### Input Validation
```python
value = request.form.get("field", "").strip().lower()
if not value or len(value) > 20 or not re.match(r'^[a-zA-Z0-9_-]+$', value):
    flash("Invalid input.", "danger")
    return redirect(url_for("route"))
```

### Caching
```python
@cache.memoize(timeout=60)
def get_data(param):
    ...

# Invalidate after data changes
cache.delete_memoized(get_data, param)
```

## Security Checklist

| Requirement | Implementation |
|-------------|----------------|
| CSRF | `{{ csrf_token() }}` in all forms |
| SQL Injection | Parameterized queries only (`?` placeholders) |
| Passwords | `generate_password_hash(pw, method="pbkdf2:sha256")` |
| Sessions | 8-hour timeout, Secure/HTTPOnly/SameSite=Strict |
| Rate Limiting | `@limiter.limit("10 per minute")` on login routes |
| Input | Strip, validate length, regex check, lowercase NetIDs |

## Database Schema (Core Tables)

| Table | Purpose |
|-------|---------|
| `users` | NetID (PK), name |
| `meal_slots` | id, date, meal_type, capacity (25 default) |
| `reservations` | id, netid, meal_slot_id, timestamp, added_by |
| `admins` | id, username, password (hashed) |
| `settings` | key-value config |
| `website_content` | Dynamic CMS content |

Capacity enforced by `limit_reservations` trigger (bypassed when `added_by` is set for admin additions).

## CLI Commands

```bash
flask init-db       # Initialize DB with default admin
flask migrate-db    # Add missing columns/tables
flask run           # Development server
```

## Common Tasks

### Add a new route
1. Choose blueprint: `routes/auth.py`, `routes/admin.py`, or `routes/main.py`
2. Follow the route pattern above
3. Add rate limiting for sensitive endpoints
4. Use `@login_required` or `@admin_required` decorators

### Modify database schema
1. Update `schema.sql`
2. Add migration logic in `utils/db.py` `migrate_db_command()`
3. Run `flask migrate-db`

### Update cached data
1. Wrap function with `@cache.memoize(timeout=60)`
2. Call `cache.delete_memoized(func, args)` after data changes

### Flash messages
Use categories: `"success"` (green), `"danger"` (red), `"warning"` (yellow), `"info"` (blue)

## Documentation Map

| Document | Purpose |
|----------|---------|
| `README.md` | User/admin guide, installation, troubleshooting |
| `AGENTS.md` | AI agent coding guidelines, style guide |
| `CHANGELOG.md` | Version history, security fixes |
| `ONBOARDING.md` | This file - quick start for developers |

## Development Notes

- **Timezone**: US Eastern (`ZoneInfo("America/New_York")`)
- **Database paths**: `meals.db` (dev), `/var/www/data/meals.db` (prod)
- **Pub nights**: Tuesday/Thursday dinners with special rules
- **Meal slots**: Auto-generated weekly via `generate_next_week_meal_slots()`
- **No test framework**: Manual testing expected

## Production Deployment

**Standard:**
```bash
export FLASK_ENV=production
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

**OpenBSD (chartermeals.com):**
```bash
# The rc.d/gunicorn_charter script handles production deployment
# Copy to /etc/rc.d/ and enable with: rcctl enable gunicorn_charter
doas rcctl start gunicorn_charter
doas rcctl restart gunicorn_charter
```

Production paths: `/var/www/htdocs/www.chartermeals.com`, `/var/www/data/meals.db`

Entry point is `app:app` for Gunicorn/WSGI.

## Maintenance Handoff Checklist

For new maintainers taking over this project:

### Access Requirements
- [ ] SSH access to production server (OpenBSD)
- [ ] GitHub repository access
- [ ] Domain registrar access (chartermeals.com)
- [ ] Club administrator contact for user lists

### First-Time Setup
- [ ] Clone repository and set up local dev environment
- [ ] Verify you can run the app locally
- [ ] Obtain production `secrets.txt` from outgoing maintainer
- [ ] Test SSH access to production server

### Semester Workflow
1. **Start of semester**: Upload new user CSV via admin panel
2. **Weekly**: Meal slots auto-generate; monitor via admin dashboard
3. **End of semester**: Use Purge tab to archive data, download archive

### Critical Files to Understand
1. `routes/main.py` - User-facing reservation logic
2. `routes/admin.py` - Admin dashboard functionality
3. `schema.sql` - Database structure and triggers
4. `rc.d/gunicorn_charter` - Production service management

### Emergency Procedures
- **App down**: `doas rcctl restart gunicorn_charter`
- **Database issues**: Check `/var/www/data/meals.db`, run `flask migrate-db`
- **Redis issues**: `redis-cli ping` (should return PONG)
- **Logs**: Check application logs for errors

### Key Contacts
- Kitchen managers: Tiffany and Hector (for meal-related questions)
- Club officers: For user list updates and policy changes
