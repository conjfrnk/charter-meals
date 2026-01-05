"""Database helper functions."""

import os
import re
import sqlite3
import logging
from flask import g, current_app
from werkzeug.security import generate_password_hash


def get_db():
    """Get database connection for the current request context."""
    if "db" not in g:
        try:
            g.db = sqlite3.connect(
                current_app.config["DATABASE"], check_same_thread=False
            )
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON;")
            g.db.execute("PRAGMA journal_mode=WAL;")
            g.db.execute("PRAGMA synchronous=NORMAL;")
            g.db.execute("PRAGMA cache_size=10000;")
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            raise RuntimeError(f"Database connection failed: {e}")
    return g.db


def close_db(error=None):
    """Close database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with schema and default admin."""
    db = get_db()
    with current_app.open_resource("schema.sql", mode="r") as f:
        db.executescript(f.read())
    # Create default admin account
    db.execute(
        "INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)",
        ("admin", generate_password_hash("admin", method="pbkdf2:sha256")),
    )
    db.commit()


def parse_schema():
    """Parse schema.sql to extract table and column definitions."""
    schema = {}
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "schema.sql"
    )
    try:
        with open(schema_path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        logging.error("schema.sql file not found")
        return schema
    except Exception as e:
        logging.error(f"Error reading schema.sql: {e}")
        return schema

    pattern = re.compile(
        r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\);", re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)
    for table, cols in matches:
        col_defs = []
        # Split by comma and remove inline comments (anything after '--')
        for line in cols.split(","):
            line = line.split("--")[0].strip()
            if not line:
                continue
            if (
                line.upper().startswith("UNIQUE")
                or line.upper().startswith("FOREIGN")
                or line.upper().startswith("CONSTRAINT")
                or line.upper().startswith("PRIMARY KEY")
            ):
                continue
            m = re.match(r"(\w+)\s+(.+)", line)
            if m:
                col_name = m.group(1)
                col_def = m.group(2).strip()
                col_defs.append((col_name, col_def))
        schema[table] = col_defs
    return schema


def get_create_statements():
    """Get CREATE TABLE statements from schema.sql."""
    create_stmts = {}
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "schema.sql"
    )
    try:
        with open(schema_path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        logging.error("schema.sql file not found")
        return create_stmts
    except Exception as e:
        logging.error(f"Error reading schema.sql: {e}")
        return create_stmts

    pattern = re.compile(
        r"(CREATE TABLE IF NOT EXISTS (\w+)\s*\(.*?\);)", re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)
    for full_stmt, table in matches:
        create_stmts[table] = full_stmt
    return create_stmts
