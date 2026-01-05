"""Application configuration settings."""

import os
from datetime import timedelta

# Base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_secret_key():
    """Load secret key from secrets.txt file."""
    secret_path = os.path.join(BASE_DIR, "secrets.txt")
    try:
        with open(secret_path, "r") as f:
            secret_key = f.read().strip()
            if not secret_key or len(secret_key) < 32:
                raise RuntimeError("Secret key must be at least 32 characters long")
            return secret_key
    except FileNotFoundError:
        raise RuntimeError(
            "Secret key file not found. Please create a 'secrets.txt' file with a generated secret key."
        )
    except Exception as e:
        raise RuntimeError(f"Error reading secret key: {str(e)}")


def get_database_path():
    """Get the appropriate database path based on environment."""
    if os.path.exists("/var/www/data"):
        return "/var/www/data/meals.db"
    return os.path.join(BASE_DIR, "meals.db")


class Config:
    """Flask application configuration."""
    
    SECRET_KEY = load_secret_key()
    
    # Session settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Database
    DATABASE = get_database_path()
    
    # Cache settings
    CACHE_TYPE = "simple"
    CACHE_DEFAULT_TIMEOUT = 300
    CACHE_THRESHOLD = 500


# Content Security Policy
CSP = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://code.jquery.com", "'unsafe-inline'"],
    "style-src": ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
}
