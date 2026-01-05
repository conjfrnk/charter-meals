# AGENTS.md - Charter Meals Codebase Guide

Guidelines for AI coding agents working in this repository.

## Project Overview

Charter Meals is a Flask web application for managing meal sign-ups for Princeton Charter Club.

| Component | Technology |
|-----------|------------|
| Backend | Python 3.8+, Flask 2.3+ |
| Database | SQLite with parameterized queries |
| Caching | Redis (Flask-Caching) |
| Templates | Jinja2 |
| Frontend | Vanilla JavaScript (ES6+), CSS3 |
| WSGI Server | Gunicorn (production) |

## Build/Run Commands

```bash
# Development setup
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask init-db      # Initialize database with default admin
flask migrate-db   # Add missing columns/tables to existing DB
flask run          # Run development server (requires secrets.txt)

# Production
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

**Testing**: No formal test framework. Manual testing expected.

**Prerequisites**:
- Redis running on `localhost:6379` (required for rate limiting)
- `secrets.txt` file with 32+ character secret key

## Code Style Guidelines

### Python

**Module Structure**:
The codebase is organized into modular components:
- `app.py` - Flask app initialization, CLI commands, template filters, error handlers
- `config.py` - Application configuration (secret key, database path, CSP)
- `extensions.py` - Flask extensions (Talisman, CSRF, limiter, cache, compress)
- `routes/` - Flask Blueprints for routes
- `utils/` - Utility functions (database, caching, helpers)

**Import Order** (blank lines between groups):
1. Standard library: `os`, `re`, `sqlite3`, `logging`, `csv`, `io`, `datetime`, `functools`
2. Flask/Werkzeug: `flask`, `werkzeug.security`
3. Local modules: `config`, `extensions`, `utils`, `routes`
4. Third-party: `zoneinfo`

**Naming Conventions**:
- Functions/variables: `snake_case` (`get_db`, `user_netid`)
- Route functions: Match URL path (`/admin/login` -> `admin_login`)
- Template filters: `*_filter` suffix (`weekday_filter`, `dayname_filter`)
- CLI commands: `*_command` suffix with hyphenated decorator name

**Route Pattern**:
```python
@app.route("/path", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # For login routes
@login_required  # or @admin_required
def route_name():
    if request.method == "POST":
        value = request.form.get("field", "").strip()
        if not value:
            flash("Field required.", "danger")
            return redirect(url_for("route_name"))
        try:
            db = get_db()
            db.execute("INSERT INTO t (col) VALUES (?)", (value,))
            db.commit()
            flash("Success.", "success")
        except Exception as e:
            logging.error(f"Error: {e}")
            flash("An error occurred.", "danger")
        return redirect(url_for("route_name"))
    return render_template("template.html")
```

**Database Queries** - Always use parameterized queries:
```python
db = get_db()
cur = db.execute("SELECT * FROM table WHERE field = ?", (param,))
result = cur.fetchone()  # or fetchall()
# For dict access: result["column_name"]
```

**Input Validation** (apply to all user inputs):
```python
value = request.form.get("field", "").strip().lower()
if not value or len(value) > 20 or not re.match(r'^[a-zA-Z0-9_-]+$', value):
    flash("Invalid input.", "danger")
    return redirect(url_for("route"))
```

**Cached Functions**:
```python
@cache.memoize(timeout=60)
def get_data(param):
    pass

# Invalidate after data changes
cache.delete_memoized(get_data, param)
```

### JavaScript (static/main.js)

- Wrap all code in `DOMContentLoaded` listener
- Use ES6+ syntax: arrow functions, `const`/`let`, template literals
- Use `camelCase` for variables/functions
- Use `dataset` attributes for DOM data (`element.dataset.tab`)
- Use `localStorage` for UI state persistence
- Add loading states to forms on submit

### CSS (static/style.css)

- BEM-like naming: `.header-left`, `.footer-blurb`, `.tabcontent`
- Mobile-first with `@media` queries
- Dark mode: `@media (prefers-color-scheme: dark)`
- Colors: Primary `#561C1D` (burgundy), Accent `#C5A144` (gold)
- Global reset at top of file

### Templates (Jinja2)

- Inheritance: `{% extends "layout.html" %}`, `{% block content %}`
- CSRF in all forms: `{{ csrf_token() }}`
- Custom filters: `{{ value|filter_name }}`
- Asset versioning: `{{ asset_url_for('filename.css') }}`

## Security Requirements

1. **CSRF**: All forms include `{{ csrf_token() }}`
2. **Rate Limiting**: Login routes use `@limiter.limit("10 per minute")`
3. **SQL**: Parameterized queries only - never string formatting/f-strings
4. **Passwords**: `generate_password_hash(password, method="pbkdf2:sha256")`
5. **Sessions**: 8-hour timeout, Secure/HTTPOnly/SameSite=Strict cookies
6. **Input**: Strip whitespace, validate length, regex check, lowercase NetIDs
7. **CSP**: Content Security Policy configured via Flask-Talisman

## File Structure

```
charter-meals/
├── app.py              # Flask app entry point (~270 lines)
├── config.py           # Application configuration
├── extensions.py       # Flask extensions initialization
├── routes/
│   ├── __init__.py     # Blueprint registration
│   ├── auth.py         # Authentication routes & decorators
│   ├── admin.py        # Admin dashboard & management routes
│   └── main.py         # User-facing routes (index, reserve)
├── utils/
│   ├── __init__.py     # Package exports
│   ├── db.py           # Database helpers (get_db, init_db, migrations)
│   ├── cache.py        # Cached data functions
│   └── helpers.py      # Utility functions (validation, parsing)
├── schema.sql          # Database schema with triggers and indexes
├── requirements.txt    # Version-pinned dependencies
├── secrets.txt         # Secret key (gitignored, min 32 chars)
├── VERSION             # Version number for cache busting
├── CHANGELOG.md        # Version history
├── rc.d/gunicorn_charter  # OpenBSD service script
├── static/
│   ├── main.js         # Frontend JavaScript
│   ├── style.css       # Styles with dark mode
│   └── pcc_logo.png
└── templates/
    ├── layout.html     # Base template
    ├── index.html      # Main meal signup
    ├── login.html, admin.html, admin_login.html, admin_change_password.html
```

## Key Patterns

**Flash Messages**: `"success"` (green), `"danger"` (red), `"warning"` (yellow), `"info"` (blue)

**CLI Commands**:
```python
@app.cli.command("command-name")
def command_name_command():
    """Docstring shown in --help."""
    pass
```

**Error Handlers**: Return redirects with flash messages (401, 404, 500)

**Decorators**: `@login_required` for users, `@admin_required` for admin routes

## Development Notes

1. Database paths: `meals.db` (dev) vs `/var/www/data/meals.db` (prod)
2. Timezone: US Eastern (`ZoneInfo("America/New_York")`)
3. Static assets use VERSION file for cache busting
4. Meal slots auto-generate weekly via `generate_next_week_meal_slots()`
5. Pub nights: Tuesday/Thursday dinners with special reservation rules
