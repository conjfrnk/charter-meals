"""Flask extensions initialization."""

from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from flask_caching import Cache

# Initialize extensions without app binding
csrf = CSRFProtect()
compress = Compress()
cache = Cache()

# Limiter needs the key function at creation
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per minute"],
    storage_uri="redis://localhost:6379/0",
)


def init_extensions(app, csp):
    """Initialize all Flask extensions with the app."""
    
    # Security: Talisman for CSP and HTTPS
    Talisman(
        app,
        content_security_policy=csp,
        force_https=False,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
    )
    
    # CSRF protection
    csrf.init_app(app)
    
    # Rate limiting
    limiter.init_app(app)
    
    # Compression
    compress.init_app(app)
    
    # Caching
    cache_config = {
        "CACHE_TYPE": app.config.get("CACHE_TYPE", "simple"),
        "CACHE_DEFAULT_TIMEOUT": app.config.get("CACHE_DEFAULT_TIMEOUT", 300),
        "CACHE_THRESHOLD": app.config.get("CACHE_THRESHOLD", 500),
    }
    cache.init_app(app, config=cache_config)
