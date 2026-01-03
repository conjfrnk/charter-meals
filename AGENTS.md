# AGENTS.md - Charter Meals Codebase Guide

This document provides guidelines for AI coding agents working in this repository.

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
flask run          # Run development server

# Production
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

**Testing**: No formal test framework. Manual testing expected.

## Code Style Guidelines

### Python (app.py)

**Import Order** (with blank lines between groups):
1. Standard library (`os`, `re`, `sqlite3`, `logging`, `datetime`, `functools`)
2. Flask/Werkzeug (`flask`, `werkzeug.security`)
3. Security extensions with comment: `# --- Security Extensions ---`
4. Performance extensions with comment: `# --- Performance Extensions ---`
5. Third-party (`zoneinfo`)

**Naming Conventions**:
- Functions/variables: `snake_case` (`get_db`, `user_netid`)
- Route functions: Match URL path (`/admin/login` -> `admin_login`)
- Template filters: `*_filter` suffix (`weekday_filter`)

**Route Pattern**:
```python
@app.route("/path", methods=["GET", "POST"])
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
```

**Input Validation**:
```python
value = request.form.get("field", "").strip().lower()
if not value or len(value) > 20 or not re.match(r'^[a-zA-Z0-9_-]+$', value):
    flash("Invalid input.", "danger")
    return redirect(url_for("route"))
```

### JavaScript (static/main.js)
- ES6+ syntax (arrow functions, `const`/`let`, template literals)
- Wrap in `DOMContentLoaded` listener
- Use `camelCase` for variables/functions

### CSS (static/style.css)
- BEM-like naming (`.header-left`, `.footer-blurb`)
- Mobile-first with `@media` queries
- Dark mode: `@media (prefers-color-scheme: dark)`
- Colors: Primary `#561C1D` (burgundy), Accent `#C5A144` (gold)

### Templates (Jinja2)
- Inheritance: `{% extends "layout.html" %}`, `{% block content %}`
- CSRF in forms: `{{ csrf_token() }}`
- Custom filters: `{{ value|filter_name }}`

## Security Requirements

1. **CSRF**: All forms include `{{ csrf_token() }}`
2. **Rate Limiting**: Login routes: `@limiter.limit("10 per minute")`
3. **SQL**: Parameterized queries only - never string formatting
4. **Passwords**: `generate_password_hash(password, method="pbkdf2:sha256")`
5. **Sessions**: 8-hour timeout, Secure/HTTPOnly/SameSite cookies
6. **Input**: Strip, validate length, regex check, lowercase NetIDs

## File Structure

```
charter-meals/
├── app.py              # Main Flask app (~1900 lines)
├── schema.sql          # Database schema with triggers
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

**Cached Functions**:
```python
@cache.memoize(timeout=60)
def get_data():
    pass

# Invalidate after data changes
cache.delete_memoized(get_data, arg1, arg2)
```

**Flash Messages**: `"success"` (green), `"danger"` (red), `"warning"` (yellow), `"info"` (blue)

**CLI Commands**:
```python
@app.cli.command("command-name")
def command_name_command():
    """Docstring."""
    pass
```

## Development Notes

1. Database: `meals.db` (dev) vs `/var/www/data/meals.db` (prod)
2. Redis required for rate limiting
3. Timezone: US Eastern (`ZoneInfo("America/New_York")`)
4. Static assets versioned via VERSION file for cache busting
