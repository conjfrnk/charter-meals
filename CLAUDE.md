# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Quick Reference

```bash
# Development setup (see ONBOARDING.md for details)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -c "import secrets; print(secrets.token_urlsafe(32))" > secrets.txt
redis-server &              # Required for rate limiting
flask init-db               # Creates DB with default admin (admin/admin)
flask run                   # Development server

# Database
flask migrate-db            # Add missing columns/tables safely

# Production
export FLASK_ENV=production
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## Architecture

**Flask meal sign-up application for Princeton Charter Club**

```
app.py              # Entry point, CLI commands, template filters, error handlers
config.py           # Configuration, CSP headers, secret key loading
extensions.py       # Flask extensions (Talisman, CSRF, Limiter, Cache, Compress)
routes/
  auth.py           # Login/logout (POST-only), @login_required, @admin_required
  main.py           # User-facing: index, meal reservations, /health endpoint
  admin.py          # Admin dashboard: users, reservations, settings, content, purge
utils/
  db.py             # get_db(), init_db(), migrations, schema parsing
  cache.py          # Memoized cache functions with invalidation helpers
  helpers.py        # CSV validation, markdown parsing, sorting utilities
schema.sql          # Database schema with triggers and indexes
rc.d/               # OpenBSD init scripts for production
```

**Tech Stack:** Python 3.9+, Flask 2.3+, SQLite, Redis (rate limiting), Jinja2, vanilla JS

## Security Requirements

**These are mandatory for all code changes:**

1. **SQL Injection Prevention** - Always use parameterized queries:
   ```python
   # CORRECT
   db.execute("SELECT * FROM users WHERE netid = ?", (netid,))

   # NEVER DO THIS
   db.execute(f"SELECT * FROM users WHERE netid = '{netid}'")
   ```

2. **CSRF Protection** - Every form needs the token:
   ```html
   <form method="post">
       {{ csrf_token() }}
       ...
   </form>
   ```

3. **Password Hashing** - Use werkzeug:
   ```python
   generate_password_hash(password, method="pbkdf2:sha256")
   check_password_hash(stored_hash, provided_password)
   ```

4. **Input Validation** - Strip and validate all user input:
   ```python
   value = request.form.get("field", "").strip()
   if not value or len(value) > 100:
       flash("Invalid input.", "danger")
       return redirect(url_for("route"))
   ```

5. **Rate Limiting** - Apply to sensitive routes:
   ```python
   @limiter.limit("10 per minute")
   ```

## Route Pattern

Standard pattern for POST routes:

```python
@bp.route("/path", methods=["GET", "POST"])
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

## Database Patterns

- Results are dict-like: `user["column_name"]`
- Foreign keys and triggers enforce integrity
- Use transactions for multi-step operations: `db.execute("BEGIN IMMEDIATE")`
- Admin reservations bypass capacity trigger when `added_by` field is set

**Cache invalidation after data changes:**
```python
cache.delete_memoized(function_name, param)
```

## Key Gotchas

- Redis must be running on localhost:6379
- Default admin credentials are admin/admin - change immediately
- Meal slot capacity is 25 by default (enforced by trigger)
- All times use US Eastern timezone: `ZoneInfo("America/New_York")`
- Session timeout is 8 hours
- Database paths differ: `meals.db` (dev) vs `/var/www/data/meals.db` (prod)

## Code Style

**Python imports** (with blank lines between groups):
1. Standard library (`os`, `re`, `sqlite3`, `logging`, `datetime`, `zoneinfo`, `threading`)
2. Flask/Werkzeug (`flask`, `werkzeug.security`)
3. Local modules (`config`, `extensions`, `utils`, `routes`)

**Flash message categories:** `"success"`, `"danger"`, `"warning"`, `"info"`

**Naming:**
- Functions/variables: `snake_case`
- Template filters: `*_filter` suffix
- CLI commands: `*_command` suffix

## Related Documentation

| File | Purpose |
|------|---------|
| `ONBOARDING.md` | Full developer setup guide |
| `README.md` | User/admin documentation, troubleshooting |
| `CHANGELOG.md` | Version history and security fixes |
| `AGENTS.md` | Extended AI coding guidelines |
