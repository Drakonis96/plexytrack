#!/usr/bin/env python3
"""
PlexyTrackt – Synchronizes Plex watched history with Trakt.

• Compatible with PlexAPI ≥ 4.15
• Safe conversion of ``viewedAt`` (datetime, numeric timestamp or string)
• Handles movies without year (``year == None``) to avoid Plex 500 errors
• Replaced ``searchShows`` (removed in PlexAPI ≥ 4.14) with generic search ``libtype="show"``
"""

import os
import json
import logging
import secrets
import hashlib
import hmac
from datetime import datetime, timezone
from numbers import Number
from typing import Dict, List, Optional, Set, Tuple, Union
from functools import wraps
import time

import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    has_request_context,
    jsonify,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_file, session
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_STOPPED
from threading import Event, Lock, Thread
from plexapi.server import PlexServer
from plexapi.myplex import MyPlexAccount
from plexapi.exceptions import BadRequest, NotFound
from getpass import getpass

# Plex moved watchlist and other account endpoints from the old
# ``metadata.provider.plex.tv`` domain to ``discover.provider.plex.tv``.
# Override the PlexAPI constant so all watchlist operations use the
# updated base URL.
MyPlexAccount.METADATA = MyPlexAccount.DISCOVER

from utils import (
    to_iso_z,
    normalize_year,
    _parse_guid_value,
    best_guid,
    imdb_guid,
    get_show_from_library,
    find_item_by_guid,
    ensure_collection,
    movie_key,
    guid_to_ids,
    valid_guid,
    trakt_movie_key,
    episode_key,
    trakt_episode_key,
    simkl_episode_key,
)
from plex_utils import (
    get_plex_history,
    update_plex,
    get_user_plex_history,
    get_user_watch_counts,
    get_owner_watch_counts,
    get_managed_user_watch_counts,
    get_owner_plex_history,
    get_managed_user_plex_history,
    load_last_plex_sync,
    save_last_plex_sync,
    load_state,
    migrate_legacy_state,
)
from trakt_utils import (
    trakt_request,
    get_trakt_history,
    update_trakt,
    sync_collection,
    sync_ratings,
    sync_liked_lists,
    sync_collections_to_trakt,
    sync_watchlist,
    fetch_trakt_history_full,
    fetch_trakt_ratings,
    fetch_trakt_watchlist,
    apply_trakt_ratings,
    restore_backup,
)
from simkl_utils import (
    simkl_request,
    simkl_search_ids,
    simkl_movie_key,
    get_simkl_history,
    update_simkl,
    sync_simkl_ratings,
    apply_simkl_ratings,
)

# --------------------------------------------------------------------------- #
# LOGGING
# --------------------------------------------------------------------------- #
# Configure root logger with a single handler to prevent duplicates
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# Remove any existing handlers to prevent duplicates
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

# Add a single console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
root_logger.addHandler(console_handler)

logger = logging.getLogger(__name__)

# Configure werkzeug (Flask's HTTP request logger) to reduce verbosity
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

# --------------------------------------------------------------------------- #
# APPLICATION INFO
# --------------------------------------------------------------------------- #
APP_NAME = "PlexyTrack"
APP_VERSION = "v0.4.7"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"

# --------------------------------------------------------------------------- #
# FLASK + APSCHEDULER
# --------------------------------------------------------------------------- #
app = Flask(__name__)
# Honor X-Forwarded headers when running behind a reverse proxy so that
# request.url_root uses the external address and scheme.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Generate a strong random secret key if not provided via env
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
# Secure session cookie settings for internet-exposed deployment
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
)


@app.context_processor
def inject_version():
    return {"app_version": APP_VERSION}

SYNC_INTERVAL_MINUTES = 60  # default frequency
SYNC_COLLECTION = False
SYNC_RATINGS = True
SYNC_WATCHED = True  # ahora sí se respeta este flag
SYNC_LIKED_LISTS = False
SYNC_WATCHLISTS = False
LIVE_SYNC = False
SYNC_PROVIDER = "none"  # trakt | simkl | none

CONFIG_DIR = os.environ.get("PLEXYTRACK_CONFIG_DIR", "/config")
STATE_DIR = os.environ.get("PLEXYTRACK_STATE_DIR", "/state")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
PROVIDER_FILE = os.path.join(CONFIG_DIR, "provider.json")
CREDENTIALS_FILE = os.path.join(CONFIG_DIR, "credentials.json")
SELECTED_USER_FILE = os.path.join(CONFIG_DIR, "selected_user.json")
SAFE_MODE = False
scheduler = BackgroundScheduler()
plex = None  # will hold PlexServer instance
plex_account = None  # will hold MyPlexAccount instance
_plex_connection_ok = False  # Flag: True after successful connection, False on failure
_sync_lock = Lock()  # Prevent concurrent sync execution

# Sync direction constants
DIRECTION_BOTH = "both"
DIRECTION_PLEX_TO_SERVICE = "plex_to_service"
DIRECTION_SERVICE_TO_PLEX = "service_to_plex"

# Default per-sync-type direction (owner only)
HISTORY_SYNC_DIRECTION = DIRECTION_BOTH
LISTS_SYNC_DIRECTION = DIRECTION_BOTH
WATCHLISTS_SYNC_DIRECTION = DIRECTION_BOTH
RATINGS_SYNC_DIRECTION = DIRECTION_BOTH
COLLECTION_SYNC_DIRECTION = DIRECTION_BOTH

# Watchlist sync behavior
WATCHLIST_CONFLICT_RESOLUTION = "last_wins"  # "last_wins" | "additive_only" | "manual"
WATCHLIST_REMOVAL_ENABLED = True

# Redirect URI management – saved URIs and active selection per service
REDIRECT_URIS = {
    "trakt": {"saved": [], "active": ""},
    "simkl": {"saved": [], "active": ""},
}

# Global storage for session-based Plex credentials (for scheduler access)
session_plex_credentials = {
    'token': None,    # Authentication token obtained via web login
    'baseurl': None   # Normalized server base URL
}

# Event used to cancel an ongoing sync
stop_event = Event()


def ensure_directory(path: str) -> None:
    """Create ``path`` with 0700 permissions if missing."""
    if not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        logger.info("Created missing directory %s; continuing start-up.", path)


def verify_volume(path: str, name: str) -> None:
    """Ensure ``path`` exists and is a mounted volume."""
    if not os.path.isdir(path):
        raise SystemExit(
            f"Required {name} directory '{path}' is missing. Bind mount a volume."
        )
    if not os.path.ismount(path):
        raise SystemExit(
            f"{name} directory '{path}' must be a mounted volume."
        )


# --------------------------------------------------------------------------- #
# AUTH / SETTINGS
# --------------------------------------------------------------------------- #
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")


# --------------------------------------------------------------------------- #
# USER AUTHENTICATION (PlexyTrack login)
# --------------------------------------------------------------------------- #
_login_attempts: Dict[str, list] = {}  # IP → list of timestamps
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 300  # 5 minutes


def _is_rate_limited(ip: str) -> bool:
    """Return True if the IP has exceeded the login attempt limit."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Remove old attempts outside the window
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    """Record a failed login attempt for rate limiting."""
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(time.time())


def load_credentials() -> dict:
    """Load user credentials from CREDENTIALS_FILE."""
    if os.path.exists(CREDENTIALS_FILE):
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Failed to load credentials: %s", exc)
    return {}


def save_credentials(data: dict) -> None:
    """Persist user credentials to CREDENTIALS_FILE."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        # Restrict file permissions so only owner can read
        os.chmod(CREDENTIALS_FILE, 0o600)
    except Exception as exc:
        logger.error("Failed to save credentials: %s", exc)


def ensure_default_credentials() -> None:
    """Create default admin/admin credentials if none exist."""
    creds = load_credentials()
    if not creds.get("username") or not creds.get("password_hash"):
        creds = {
            "username": "admin",
            "password_hash": generate_password_hash(
                "admin", method="pbkdf2:sha256", salt_length=16
            ),
        }
        save_credentials(creds)
        logger.info("Default credentials created (admin/admin). Change the password!")


def verify_credentials(username: str, password: str) -> bool:
    """Verify username/password against stored credentials."""
    creds = load_credentials()
    stored_user = creds.get("username", "")
    stored_hash = creds.get("password_hash", "")
    if not stored_user or not stored_hash:
        return False
    # Constant-time comparison for username
    user_ok = hmac.compare_digest(username.lower(), stored_user.lower())
    pass_ok = check_password_hash(stored_hash, password)
    return user_ok and pass_ok


def login_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("authenticated"):
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function


# --------------------------------------------------------------------------- #
# PROVIDER SELECTION
# --------------------------------------------------------------------------- #
def load_provider() -> None:
    """Load selected sync provider from file."""
    global SYNC_PROVIDER
    if os.path.exists(PROVIDER_FILE):
        try:
            with open(PROVIDER_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            SYNC_PROVIDER = data.get("provider", "none")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load provider: %s", exc)


def save_provider(provider: str) -> None:
    """Persist selected sync provider to file."""
    global SYNC_PROVIDER
    SYNC_PROVIDER = provider
    try:
        with open(PROVIDER_FILE, "w", encoding="utf-8") as f:
            json.dump({"provider": provider}, f, indent=2)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to save provider: %s", exc)


# --------------------------------------------------------------------------- #
# PERSISTENT SETTINGS
# --------------------------------------------------------------------------- #
def load_settings() -> None:
    """Load sync settings from :data:`SETTINGS_FILE` if present."""
    global SYNC_INTERVAL_MINUTES, SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED
    global SYNC_LIKED_LISTS, SYNC_WATCHLISTS, LIVE_SYNC
    global HISTORY_SYNC_DIRECTION, LISTS_SYNC_DIRECTION
    global WATCHLISTS_SYNC_DIRECTION, RATINGS_SYNC_DIRECTION, COLLECTION_SYNC_DIRECTION
    global WATCHLIST_CONFLICT_RESOLUTION, WATCHLIST_REMOVAL_ENABLED
    global REDIRECT_URIS
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            SYNC_INTERVAL_MINUTES = int(data.get("minutes", SYNC_INTERVAL_MINUTES))
            SYNC_COLLECTION = data.get("collection", SYNC_COLLECTION)
            SYNC_RATINGS = data.get("ratings", SYNC_RATINGS)
            SYNC_WATCHED = data.get("watched", SYNC_WATCHED)
            SYNC_LIKED_LISTS = data.get("liked_lists", SYNC_LIKED_LISTS)
            SYNC_WATCHLISTS = data.get("watchlists", SYNC_WATCHLISTS)
            LIVE_SYNC = data.get("live_sync", LIVE_SYNC)
            HISTORY_SYNC_DIRECTION = data.get("history_direction", HISTORY_SYNC_DIRECTION)
            LISTS_SYNC_DIRECTION = data.get("lists_direction", LISTS_SYNC_DIRECTION)
            WATCHLISTS_SYNC_DIRECTION = data.get(
                "watchlists_direction", WATCHLISTS_SYNC_DIRECTION
            )
            RATINGS_SYNC_DIRECTION = data.get("ratings_direction", RATINGS_SYNC_DIRECTION)
            COLLECTION_SYNC_DIRECTION = data.get(
                "collection_direction", COLLECTION_SYNC_DIRECTION
            )
            WATCHLIST_CONFLICT_RESOLUTION = data.get("watchlist_conflict_resolution", WATCHLIST_CONFLICT_RESOLUTION)
            WATCHLIST_REMOVAL_ENABLED = data.get("watchlist_removal_enabled", WATCHLIST_REMOVAL_ENABLED)
            # Redirect URIs
            stored_uris = data.get("redirect_uris")
            if stored_uris and isinstance(stored_uris, dict):
                for svc in ("trakt", "simkl"):
                    if svc in stored_uris and isinstance(stored_uris[svc], dict):
                        REDIRECT_URIS[svc]["saved"] = stored_uris[svc].get("saved", [])
                        REDIRECT_URIS[svc]["active"] = stored_uris[svc].get("active", "")
            logger.info("Loaded sync settings from %s", SETTINGS_FILE)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load settings: %s", exc)


def save_settings() -> None:
    """Persist current sync settings to :data:`SETTINGS_FILE`."""
    data = {
        "minutes": SYNC_INTERVAL_MINUTES,
        "collection": SYNC_COLLECTION,
        "ratings": SYNC_RATINGS,
        "watched": SYNC_WATCHED,
        "liked_lists": SYNC_LIKED_LISTS,
        "watchlists": SYNC_WATCHLISTS,
        "live_sync": LIVE_SYNC,
        "history_direction": HISTORY_SYNC_DIRECTION,
        "lists_direction": LISTS_SYNC_DIRECTION,
        "watchlists_direction": WATCHLISTS_SYNC_DIRECTION,
        "ratings_direction": RATINGS_SYNC_DIRECTION,
        "collection_direction": COLLECTION_SYNC_DIRECTION,
        "watchlist_conflict_resolution": WATCHLIST_CONFLICT_RESOLUTION,
        "watchlist_removal_enabled": WATCHLIST_REMOVAL_ENABLED,
        "redirect_uris": REDIRECT_URIS,
    }
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved sync settings to %s", SETTINGS_FILE)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to save settings: %s", exc)


# --------------------------------------------------------------------------- #
# CUSTOM EXCEPTIONS
# --------------------------------------------------------------------------- #
class TraktAccountLimitError(Exception):
    """Raised when Trakt returns HTTP 420 (account limit exceeded)."""

    pass


def get_trakt_redirect_uri() -> str:
    """Return the Trakt redirect URI.

    Priority: 1) active URI from settings, 2) env var, 3) request-based, 4) default.
    """
    # 1. Active URI saved via the UI
    active = REDIRECT_URIS.get("trakt", {}).get("active", "")
    if active:
        return active
    # 2. Environment variable
    uri = os.environ.get("TRAKT_REDIRECT_URI")
    if uri:
        return uri
    if has_request_context():
        return request.url_root.rstrip("/") + "/oauth/trakt"
    return "http://localhost:5030/oauth/trakt"


def get_simkl_redirect_uri() -> str:
    """Return the Simkl redirect URI.

    Priority: 1) active URI from settings, 2) env var, 3) request-based, 4) default.
    """
    # 1. Active URI saved via the UI
    active = REDIRECT_URIS.get("simkl", {}).get("active", "")
    if active:
        return active
    # 2. Environment variable
    uri = os.environ.get("SIMKL_REDIRECT_URI")
    if uri:
        return uri
    if has_request_context():
        return request.url_root.rstrip("/") + "/oauth/simkl"
    return "http://localhost:5030/oauth/simkl"


def normalize_baseurl(url: Optional[str]) -> Optional[str]:
    """Ensure the Plex base URL includes a scheme and no trailing slash."""
    if not url:
        return None
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _build_plex_session() -> requests.Session:
    """Return a configured requests.Session for Plex connections.

    Honors env PLEX_VERIFY_SSL (true/false). Defaults to False to support
    connecting via https to IPs without valid certs. Disables proxy inheritance
    from the environment to avoid accidental rerouting.
    """
    sess = requests.Session()
    verify_env = os.environ.get("PLEX_VERIFY_SSL", "false").strip().lower()
    sess.verify = verify_env in ("1", "true", "yes", "on")
    # Avoid environment proxies interfering with local connections
    sess.trust_env = False
    return sess


def get_plex_server_legacy():
    """
    Legacy fallback method using token authentication.
    Used when credentials are not provided.
    """
    baseurl = normalize_baseurl(os.environ.get("PLEX_BASEURL"))
    token = os.environ.get("PLEX_TOKEN")
    if not baseurl or not token:
        return None
    try:
        from plexapi.server import PlexServer
        return PlexServer(baseurl, token, session=_build_plex_session())
    except Exception as exc:
        logger.error("Failed to connect to Plex using legacy token method: %s", exc)
        return None


def get_plex_server():
    """Return a connected :class:`PlexServer` instance or ``None``."""
    global plex, plex_account, _plex_connection_ok
    if plex is None:
        from flask import has_request_context, session
        token = None
        baseurl = None

        if has_request_context():
            token = session.get('plex_token')
            baseurl = session.get('plex_baseurl')

        if not token or not baseurl:
            stored_token, stored_baseurl = get_session_credentials()
            token = token or stored_token
            baseurl = baseurl or stored_baseurl

        if not baseurl:
            baseurl = os.environ.get("PLEX_BASEURL")
        baseurl = normalize_baseurl(baseurl)

        if not token:
            token = os.environ.get("PLEX_TOKEN")

        if not token or not baseurl:
            logger.error("Missing Plex token or base URL for connection")
            return None

        if token and baseurl:
            try:
                from plexapi.server import PlexServer
                plex = PlexServer(baseurl, token, session=_build_plex_session())
                # Create MyPlexAccount only when absolutely necessary, and cache the account ID
                try:
                    temp_account = MyPlexAccount(token=token)
                    # Cache the account ID to avoid future auto-discovery calls
                    plex._cached_account_id = temp_account.id
                    plex_account = temp_account
                except Exception as acc_exc:
                    logger.warning("Could not create MyPlexAccount: %s", acc_exc)
                    plex_account = None
                    if plex:
                        plex._cached_account_id = None
                _plex_connection_ok = True
                logger.info("Successfully connected to Plex using token and configured base URL")
                return plex
            except Exception as exc:
                logger.warning("Token-based authentication failed: %s", exc)
                plex = None

        # Last resort: método legacy con token
        legacy = get_plex_server_legacy()
        if legacy is not None:
            plex = legacy
            _plex_connection_ok = True
        else:
            _plex_connection_ok = False
        plex_account = None

    return plex


def get_plex_account():
    """Return the authenticated MyPlexAccount instance or None."""
    global plex_account
    # Ensure server connection is established first (which also sets up the account)
    get_plex_server()
    return plex_account


# --------------------------------------------------------------------------- #
# UTILITIES
# --------------------------------------------------------------------------- #
def to_iso_z(value) -> Optional[str]:
    """Convert any ``viewedAt`` variant to ISO-8601 UTC ("...Z")."""
    if value is None:
        return None

    if isinstance(value, datetime):  # datetime / pendulum / arrow
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    if isinstance(value, Number):  # int / float
        return datetime.utcfromtimestamp(value).isoformat() + "Z"

    if isinstance(value, str):  # str
        try:  # integer as text
            return datetime.utcfromtimestamp(int(value)).isoformat() + "Z"
        except (TypeError, ValueError):
            pass
        try:  # ISO string
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    logger.warning("Unrecognized viewedAt format: %r (%s)", value, type(value))
    return None


def normalize_year(value: Union[str, int, None]) -> Optional[int]:
    """Return ``value`` as ``int`` if possible, otherwise ``None``."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.debug("Invalid year value: %r", value)
        return None




# --------------------------------------------------------------------------- #
# TRAKT TOKENS
# --------------------------------------------------------------------------- #
def load_auth() -> dict:
    """Load authentication tokens from :data:`AUTH_FILE`."""
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load auth file: %s", exc)
    return {}


def save_auth(data: dict) -> None:
    """Persist authentication tokens to :data:`AUTH_FILE`."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to save auth file: %s", exc)


def load_trakt_tokens() -> bool:
    auth = load_auth()
    tokens = auth.get("trakt")
    if tokens:
        os.environ["TRAKT_ACCESS_TOKEN"] = tokens.get("access_token", "")
        os.environ["TRAKT_REFRESH_TOKEN"] = tokens.get("refresh_token", "")
        os.environ["TRAKT_EXPIRES_AT"] = str(tokens.get("expires_at", ""))
        logger.info("Loaded Trakt tokens from %s", AUTH_FILE)
        return True
    return False


def save_trakt_tokens(
    access_token: str, refresh_token: Optional[str], expires_in: Optional[int] = None
) -> None:
    auth = load_auth()
    auth["trakt"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": int(time.time()) + int(expires_in) if expires_in else None,
    }
    save_auth(auth)
    logger.info("Saved Trakt tokens to %s", AUTH_FILE)


def exchange_code_for_tokens(code: str) -> Optional[dict]:
    client_id = os.environ.get("TRAKT_CLIENT_ID")
    client_secret = os.environ.get("TRAKT_CLIENT_SECRET")
    if not all([code, client_id, client_secret]):
        logger.error("Missing code or Trakt client credentials.")
        return None

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": get_trakt_redirect_uri(),
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post(
            "https://api.trakt.tv/oauth/token",
            json=payload,
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Failed to obtain Trakt tokens: %s", exc)
        return None

    data = resp.json()
    os.environ["TRAKT_ACCESS_TOKEN"] = data["access_token"]
    os.environ["TRAKT_REFRESH_TOKEN"] = data.get("refresh_token")
    save_trakt_tokens(
        data["access_token"],
        data.get("refresh_token"),
        data.get("expires_in"),
    )
    logger.info("Trakt tokens obtained via authorization code")
    return data


def refresh_trakt_token() -> Optional[str]:
    refresh_token = os.environ.get("TRAKT_REFRESH_TOKEN")
    client_id = os.environ.get("TRAKT_CLIENT_ID")
    client_secret = os.environ.get("TRAKT_CLIENT_SECRET")
    if not all([refresh_token, client_id, client_secret]):
        logger.error("Missing Trakt OAuth environment variables.")
        return None

    payload = {
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": get_trakt_redirect_uri(),
        "grant_type": "refresh_token",
    }
    try:
        resp = requests.post(
            "https://api.trakt.tv/oauth/token",
            json=payload,
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Failed to refresh Trakt token: %s", exc)
        return None

    data = resp.json()
    os.environ["TRAKT_ACCESS_TOKEN"] = data["access_token"]
    os.environ["TRAKT_REFRESH_TOKEN"] = data.get("refresh_token", refresh_token)
    save_trakt_tokens(
        data["access_token"],
        os.environ["TRAKT_REFRESH_TOKEN"],
        data.get("expires_in"),
    )
    logger.info("Trakt access token refreshed")
    return data["access_token"]


def load_plex_token() -> bool:
    """Load Plex token + base URL from auth.json if available."""
    auth = load_auth()
    plex_data = auth.get("plex")
    if plex_data:
        token = plex_data.get("token", "")
        baseurl = plex_data.get("baseurl", "")
        if token:
            os.environ["PLEX_TOKEN"] = token
            if baseurl:
                os.environ["PLEX_BASE_URL"] = baseurl
            save_session_credentials(token, baseurl)
            logger.info("Loaded Plex token from %s", AUTH_FILE)
            return True
    return False


def save_plex_token(token: str, baseurl: str = "") -> None:
    """Persist Plex token + base URL to auth.json."""
    auth = load_auth()
    auth["plex"] = {
        "token": token,
        "baseurl": baseurl,
    }
    save_auth(auth)
    logger.info("Saved Plex token to %s", AUTH_FILE)


def load_simkl_tokens() -> bool:
    auth = load_auth()
    tokens = auth.get("simkl")
    if tokens:
        os.environ["SIMKL_ACCESS_TOKEN"] = tokens.get("access_token", "")
        os.environ["SIMKL_EXPIRES_AT"] = str(tokens.get("expires_at", ""))
        logger.info("Loaded Simkl token from %s", AUTH_FILE)
        return True
    return False


def save_simkl_token(
    access_token: str,
    refresh_token: Optional[str] = None,
    expires_in: Optional[int] = None,
) -> None:
    auth = load_auth()
    auth["simkl"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": int(time.time()) + int(expires_in) if expires_in else None,
    }
    save_auth(auth)
    logger.info("Saved Simkl token to %s", AUTH_FILE)


def exchange_code_for_simkl_tokens(code: str) -> Optional[dict]:
    client_id = os.environ.get("SIMKL_CLIENT_ID")
    client_secret = os.environ.get("SIMKL_CLIENT_SECRET")
    if not all([code, client_id, client_secret]):
        logger.error("Missing code or Simkl client credentials.")
        return None

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": get_simkl_redirect_uri(),
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post(
            "https://api.simkl.com/oauth/token",
            json=payload,
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Failed to obtain Simkl token: %s", exc)
        return None

    data = resp.json()
    os.environ["SIMKL_ACCESS_TOKEN"] = data["access_token"]
    save_simkl_token(
        data["access_token"],
        data.get("refresh_token"),
        data.get("expires_in"),
    )
    logger.info("Simkl token obtained via authorization code")
    return data



def trakt_request(
    method: str, endpoint: str, headers: dict, **kwargs
) -> requests.Response:
    url = f"https://api.trakt.tv{endpoint}"

    headers.setdefault("User-Agent", USER_AGENT)

    resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    if resp.status_code == 401:  # token expired
        new_token = refresh_trakt_token()
        if new_token:
            headers["Authorization"] = f"Bearer {new_token}"
            resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

    if resp.status_code == 420:
        msg = (
            "Trakt API returned 420 – account limit exceeded. "
            "Upgrade to VIP or reduce the size of your collection/watchlist."
        )
        logger.warning(msg)
        raise TraktAccountLimitError(msg)

    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "1"))
        logger.warning(
            "Trakt API rate limit reached. Retrying in %s seconds", retry_after
        )
        time.sleep(retry_after)
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

    resp.raise_for_status()
    return resp


def trakt_search_ids(
    headers: dict,
    title: str,
    *,
    is_movie: bool = True,
    year: Optional[int] = None,
) -> Dict[str, Union[str, int]]:
    """Search Trakt by title and return a mapping of IDs.

    If no clear result is found, returns an empty dict.
    """
    # Use text search endpoint
    params = {"query": title, "type": "movie" if is_movie else "show", "limit": 1}
    # Trakt search supports year filtering
    if year and is_movie:
        params["year"] = year
    try:
        resp = trakt_request("GET", "/search/text", headers, params=params)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Trakt search failed for '%s': %s", title, exc)
        return {}

    if not isinstance(data, list) or not data:
        return {}

    # Extract the media item from the search result
    result = data[0]
    media_type = "movie" if is_movie else "show"
    media_item = result.get(media_type, {})
    
    ids = media_item.get("ids", {}) or {}
    # Normalize integer IDs
    for k, v in list(ids.items()):
        try:
            ids[k] = int(v) if str(v).isdigit() else v
        except Exception:
            pass
    return ids


# --------------------------------------------------------------------------- #
# SCHEDULER TASK
# --------------------------------------------------------------------------- #
def validate_bidirectional_sync_config():
    """
    Validate that bidirectional sync is properly configured and warn about any issues.
    """
    selected_user = load_selected_user()
    if not selected_user:
        logger.warning("Bidirectional sync validation: No user selected")
        return False
    
    if not selected_user.get("is_owner", False):
        logger.info("Bidirectional sync validation: User '%s' is a managed user - bidirectional sync will be skipped", 
                   selected_user.get("username", "Unknown"))
        logger.info("Note: Only owner accounts support bidirectional sync (Trakt/Simkl -> Plex)")
        return False
    
    logger.debug("Bidirectional sync validation: User '%s' is owner - bidirectional sync enabled",
                selected_user.get("username", "Unknown"))
    return True


def sync_watchlists_only(
    plex=None,
    headers=None,
    plex_history=None,
    trakt_history=None,
):
    """Synchronize Plex and Trakt watchlists without history sync."""
    logger.debug("Starting watchlist-only sync...")
    
    if stop_event.is_set():
        logger.info("Sync cancelled")
        return

    plex_history = plex_history or set()
    trakt_history = trakt_history or set()
    
    logger.debug("Plex history size: %d, Trakt history size: %d", len(plex_history), len(trakt_history))

    # Allow standalone execution without pre-initialized clients
    if plex is None or headers is None:
        logger.debug("Initializing clients for standalone watchlist sync...")
        if SYNC_PROVIDER != "trakt":
            logger.warning("Watchlist sync is only supported with Trakt provider.")
            return
        reset_cache()
        if not test_connections():
            logger.error("Watchlist sync cancelled due to connection errors.")
            return
        if plex is None:
            logger.debug("Getting Plex server...")
            plex = get_plex_server()
            if plex is None:
                logger.error("No Plex server available for watchlist sync")
                return
        if headers is None:
            logger.debug("Setting up Trakt headers...")
            if not refresh_trakt_token():
                logger.error("Failed to refresh Trakt token. Aborting watchlist sync.")
                return
            load_trakt_tokens()
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ.get('TRAKT_ACCESS_TOKEN')}",
                "trakt-api-version": "2",
                "trakt-api-key": os.environ["TRAKT_CLIENT_ID"],
            }

    logger.debug("Calling sync_watchlist function...")
    try:
        sync_watchlist(
            plex,
            headers,
            plex_history,
            trakt_history,
            direction=WATCHLISTS_SYNC_DIRECTION,
        )
        logger.debug("Watchlist sync completed successfully")
    except TraktAccountLimitError as exc:
        logger.error("Watchlist sync skipped: %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.error("Watchlist sync failed: %s", exc)
        import traceback
        logger.debug("Watchlist sync traceback: %s", traceback.format_exc())
    else:
        mirror_trakt_watchlist_to_simkl(headers)


def mirror_trakt_watchlist_to_simkl(headers) -> None:
    """Mirror current Trakt watchlist items into Simkl plan-to-watch list."""
    try:
        simkl_token = os.environ.get("SIMKL_ACCESS_TOKEN")
        simkl_client_id = os.environ.get("SIMKL_CLIENT_ID")
        if not (simkl_token and simkl_client_id):
            return

        from simkl_utils import add_items_to_simkl_list

        trakt_watchlist = fetch_trakt_watchlist(headers)
        movies_payload = []
        shows_payload = []

        for it in trakt_watchlist.get("movies", []) or []:
            mv = it.get("movie", {}) if isinstance(it, dict) else {}
            ids = mv.get("ids", {}) or {}
            obj = {"title": mv.get("title"), "ids": ids}
            year = normalize_year(mv.get("year"))
            if year is not None:
                obj["year"] = year
            movies_payload.append(obj)

        for it in trakt_watchlist.get("shows", []) or []:
            sh = it.get("show", {}) if isinstance(it, dict) else {}
            ids = sh.get("ids", {}) or {}
            obj = {"title": sh.get("title"), "ids": ids}
            year = normalize_year(sh.get("year"))
            if year is not None:
                obj["year"] = year
            shows_payload.append(obj)

        if movies_payload or shows_payload:
            simkl_headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {simkl_token}",
                "simkl-api-key": simkl_client_id,
            }
            add_items_to_simkl_list(
                simkl_headers,
                movies=movies_payload if movies_payload else None,
                shows=shows_payload if shows_payload else None,
                target_list="plantowatch",
            )
            logger.info(
                "Mirrored %d Trakt watchlist movies and %d shows to Simkl plan-to-watch",
                len(movies_payload),
                len(shows_payload),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not mirror Trakt watchlist to Simkl: %s", exc)


def sync():
    """Run the main synchronization logic with selected user."""
    if not _sync_lock.acquire(blocking=False):
        logger.warning("Sync already in progress, skipping this run")
        return
    try:
        _sync_inner()
    except Exception as exc:
        import traceback
        logger.error("Sync crashed with unhandled exception: %s", exc)
        logger.error("Traceback: %s", traceback.format_exc())
    finally:
        _sync_lock.release()


def _sync_inner():
    """Internal sync logic (called under _sync_lock)."""
    if stop_event.is_set():
        logger.info("Sync aborted before start")
        return
    # Reset cache to ensure fresh data on every sync start
    reset_cache()
    
    if not test_connections():
        logger.error("Sync cancelled due to connection errors.")
        return

    # Capture a local reference to the Plex server to avoid race conditions
    # (e.g. re-auth or logout in another thread setting global plex to None)
    sync_plex = plex
    if sync_plex is None:
        logger.error("Plex server not available after connection test. Aborting sync.")
        return

    # Check if a user is selected for sync
    selected_user = load_selected_user()
    if not selected_user:
        logger.error("No user selected for sync. Please select a user first.")
        return

    logger.info("Starting sync for user: %s (%s)", selected_user["username"], selected_user["role"])
    
    # Validate bidirectional sync configuration
    validate_bidirectional_sync_config()
    
    # Reload all tokens (Plex token may have been saved to auth.json)
    load_plex_token()
    trakt_enabled = load_trakt_tokens()
    simkl_enabled = load_simkl_tokens()

    headers = {}
    if SYNC_PROVIDER == "trakt" and trakt_enabled:
        if not refresh_trakt_token():
            logger.error("Failed to refresh Trakt token. Aborting sync.")
            return
        load_trakt_tokens()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('TRAKT_ACCESS_TOKEN')}",
            "trakt-api-version": "2",
            "trakt-api-key": os.environ["TRAKT_CLIENT_ID"],
        }
    elif SYNC_PROVIDER == "simkl" and simkl_enabled:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ.get('SIMKL_ACCESS_TOKEN')}",
            "simkl-api-key": os.environ["SIMKL_CLIENT_ID"],
        }

    # Get history for the selected user
    account = get_plex_account()
    if account is None:
        logger.error("No Plex account available for sync")
        return

    try:
        # Load lastSync once so both Plex and Trakt use the same window
        last_sync = load_last_plex_sync()
        is_incremental = last_sync is not None

        # Trakt truncates watched_at to the nearest minute, so we subtract a
        # 2-minute safety margin to avoid missing items added near the boundary.
        trakt_date_from = None
        if last_sync:
            try:
                from datetime import timedelta
                ls_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                trakt_date_from = (ls_dt - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
            except Exception:
                trakt_date_from = last_sync

        if SYNC_PROVIDER == "trakt":
            logger.info("Provider: Trakt")
            try:
                # Use incremental Trakt fetch when lastSync exists so that
                # bidirectional comparison uses the same time window as Plex.
                trakt_movies, trakt_episodes = get_trakt_history(
                    headers, date_from=trakt_date_from
                )
            except Exception as exc:
                logger.error("Failed to retrieve Trakt history: %s", exc)
                trakt_movies, trakt_episodes = {}, {}

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            
            # Fetch Plex history (incremental if lastSync exists, full on first run)
            plex_movies, plex_episodes = get_selected_user_history(mindate=last_sync)
            logger.info("Found %d movies and %d episodes in Plex history.",
                       len(plex_movies), len(plex_episodes))
            plex_movie_guids = set(plex_movies.keys())
            plex_episode_guids = set(plex_episodes.keys())
            trakt_movie_guids = set(trakt_movies.keys())
            trakt_episode_guids = set(trakt_episodes.keys())

            logger.info(
                "Plex history:   %d movies, %d episodes",
                len(plex_movie_guids),
                len(plex_episode_guids),
            )
            logger.info(
                "Trakt history:  %d movies, %d episodes",
                len(trakt_movie_guids),
                len(trakt_episode_guids),
            )

            # Always do full sync for Plex - compare against what's already in Trakt
            # This ensures reliable episode detection without timestamp comparison issues
            new_movies = [
                (data["title"], data["year"], data.get("watched_at"), guid)
                for guid, data in plex_movies.items()
                if guid not in trakt_movie_guids
            ]
            new_episodes = [
                (data["show"], data["code"], data.get("watched_at"), guid)
                for guid, data in plex_episodes.items()
                if guid not in trakt_episode_guids
            ]

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return

            if SYNC_WATCHED and HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_PLEX_TO_SERVICE):
                try:
                    update_trakt(headers, new_movies, new_episodes)
                except Exception as exc:
                    logger.error("Failed updating Trakt history: %s", exc)

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return

            missing_movies = {
                (title, year, guid)
                for guid, (title, year, *_rest) in trakt_movies.items()
                if guid not in plex_movie_guids
            }
            missing_episodes = {
                (show, code, guid)
                for guid, (show, code, *_rest) in trakt_episodes.items()
                if guid not in plex_episode_guids
            }
            
            # Bidirectional sync: Mark missing items as watched for selected user (only for owner users)
            if HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX) and selected_user.get("is_owner", False):
                # Safety: if Plex returned 0 items but provider has many, the Plex
                # connection likely failed — skip bidirectional sync entirely.
                # Only applies to FULL syncs; during incremental syncs, 0 items is
                # normal when nothing new has been watched since lastSync.
                if not _plex_connection_ok:
                    logger.warning("Skipping bidirectional sync: Plex connection was not verified successfully.")
                elif not is_incremental and len(plex_movie_guids) == 0 and len(plex_episode_guids) == 0 and (len(trakt_movie_guids) > 0 or len(trakt_episode_guids) > 0):
                    logger.warning("Skipping bidirectional sync: Plex returned 0 items while Trakt has %d. "
                                   "This likely indicates a Plex connection issue.", 
                                   len(trakt_movie_guids) + len(trakt_episode_guids))
                elif missing_movies or missing_episodes:
                    total_items = len(missing_movies) + len(missing_episodes)
                    
                    # Safety check: if too many items, limit for safety
                    if total_items > 100:
                        logger.warning("Bidirectional sync wants to mark %d items as watched. This is a large number!", total_items)
                        logger.warning("This might indicate that your Plex history isn't being read correctly.")
                        logger.warning("Consider checking your Plex connection and running a manual sync first.")
                        
                        # For safety, limit to first 50 items of each type
                        missing_movies = list(missing_movies)[:50]
                        missing_episodes = list(missing_episodes)[:50]
                        logger.warning("Limiting bidirectional sync to first 50 movies and 50 episodes for safety.")
                    
                    start_time = time.time()
                    logger.info("Bidirectional sync: Marking %d movies and %d episodes as watched for user %s (%s)", 
                               len(missing_movies), len(missing_episodes), 
                               selected_user["username"], selected_user["role"])
                    
                    # Batch process movies - collect results first
                    movie_start = time.time()
                    movie_results = []
                    for title, year, guid in missing_movies:
                        if stop_event.is_set():
                            logger.info("Sync cancelled")
                            return
                        try:
                            if mark_as_watched_for_user(
                                guid,
                                "movie",
                                selected_user,
                                title=title,
                                year=year,
                            ):
                                movie_results.append((title, year, True))
                                logger.debug("Marked movie as watched: %s (%s)", title, year)
                            else:
                                movie_results.append((title, year, False))
                        except Exception as exc:
                            logger.warning("Failed to mark movie as watched for %s: %s (%s) - %s", 
                                         selected_user["username"], title, year, exc)
                            movie_results.append((title, year, False))
                    movie_duration = time.time() - movie_start
                    
                    # Batch process episodes - collect results first
                    episode_start = time.time()
                    episode_results = []
                    for show, code, guid in missing_episodes:
                        if stop_event.is_set():
                            logger.info("Sync cancelled")
                            return
                        try:
                            if mark_as_watched_for_user(
                                guid,
                                "episode",
                                selected_user,
                                show_title=show,
                                code=code,
                            ):
                                episode_results.append((show, code, True))
                                logger.debug("Marked episode as watched: %s %s", show, code)
                            else:
                                episode_results.append((show, code, False))
                        except Exception as exc:
                            logger.warning("Failed to mark episode as watched for %s: %s %s - %s", 
                                         selected_user["username"], show, code, exc)
                            episode_results.append((show, code, False))
                    episode_duration = time.time() - episode_start
                    
                    # Log summary of results with timing
                    successful_movies = sum(1 for _, _, success in movie_results if success)
                    successful_episodes = sum(1 for _, _, success in episode_results if success)
                    total_duration = time.time() - start_time
                    
                    logger.info("Bidirectional sync completed: %d/%d movies (%.1fs) and %d/%d episodes (%.1fs) marked as watched for %s (total: %.1fs)",
                               successful_movies, len(missing_movies), movie_duration,
                               successful_episodes, len(missing_episodes), episode_duration,
                               selected_user["username"], total_duration)
            elif HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX):
                if missing_movies or missing_episodes:
                    logger.info("Skipping bidirectional sync for managed user %s: %d movies and %d episodes would have been synced from Trakt to Plex",
                               selected_user["username"], len(missing_movies), len(missing_episodes))

        elif SYNC_PROVIDER == "simkl":
            logger.info("Provider: Simkl")
            simkl_movies, simkl_episodes = get_simkl_history(
                headers, date_from=last_sync
            )
            logger.info(
                "Retrieved %d movies and %d episodes from Simkl",
                len(simkl_movies),
                len(simkl_episodes),
            )

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            
            # Fetch Plex history (incremental if lastSync exists, full on first run)
            plex_movies, plex_episodes = get_selected_user_history(mindate=last_sync)
            logger.info("Found %d movies and %d episodes in Plex history.",
                       len(plex_movies), len(plex_episodes))

            # Filter out items already on Simkl to avoid redundant API calls
            simkl_movie_guids = set(simkl_movies)
            simkl_episode_guids = set(simkl_episodes)
            movies_to_add = set(plex_movies) - simkl_movie_guids

            # Episode keys differ between Plex (episode-level GUID like
            # "imdb://tt10864014") and Simkl (show-level tuple like
            # ("imdb://tt9055008", "S01E03")).  Build a secondary lookup
            # by (show_title, code) to catch matches across key formats.
            simkl_episodes_by_show_code = set()
            for _guid, (_show_title, _code, _wa) in simkl_episodes.items():
                if isinstance(_show_title, str):
                    simkl_episodes_by_show_code.add((_show_title.lower(), _code.upper()))

            episodes_to_add = set()
            for e_key in set(plex_episodes):
                if e_key in simkl_episode_guids:
                    continue
                ep_info = plex_episodes[e_key]
                show_code = (ep_info["show"].lower(), ep_info["code"].upper())
                if show_code in simkl_episodes_by_show_code:
                    continue
                episodes_to_add.add(e_key)
                episodes_to_add.add(e_key)

            logger.info(
                "Found %d movies and %d episodes to add to Simkl",
                len(movies_to_add),
                len(episodes_to_add),
            )

            movies_to_add_fmt = [
                (
                    plex_movies[m]["title"],
                    plex_movies[m]["year"],
                    m,
                    plex_movies[m].get("watched_at"),
                )
                for m in movies_to_add
            ]

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            # Para cada episodio necesitamos el GUID de la SERIE (no el del episodio) para que Simkl pueda identificarla correctamente.
            episodes_to_add_fmt = []
            for e in episodes_to_add:
                if stop_event.is_set():
                    logger.info("Sync cancelled")
                    return
                ep_info = plex_episodes[e]
                show_title = ep_info["show"]
                code = ep_info["code"]
                watched_at = ep_info.get("watched_at")

                # Intentamos obtener la serie desde la biblioteca de Plex para extraer un GUID válido (imdb/tmdb/tvdb) a nivel de serie.
                show_guid = None
                try:
                    show_obj = get_show_from_library(sync_plex, show_title)
                    if show_obj:
                        show_guid = imdb_guid(show_obj) or best_guid(show_obj)
                except Exception as exc:
                    logger.debug("Failed to obtain GUID for show %s: %s", show_title, exc)

                # Si seguimos sin GUID de serie, recurrimos al GUID del episodio como último recurso.
                if show_guid is None:
                    show_guid = e

                episodes_to_add_fmt.append(
                    (
                        show_title,
                        code,
                        show_guid,
                        watched_at,
                    )
                )
            
            if SYNC_WATCHED and HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_PLEX_TO_SERVICE):
                if movies_to_add_fmt or episodes_to_add_fmt:
                    update_simkl(headers, movies_to_add_fmt, episodes_to_add_fmt)

            if stop_event.is_set():
                logger.info("Sync cancelled")
                return

            # Plex <- Simkl (only for owner users)
            if HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX) and selected_user.get("is_owner", False):
                # Safety: skip if Plex connection is suspect or incremental sync returned 0 items
                if not _plex_connection_ok:
                    logger.warning("Skipping bidirectional sync (Simkl -> Plex): Plex connection was not verified successfully.")
                elif not is_incremental and len(plex_movies) == 0 and len(plex_episodes) == 0 and (len(simkl_movies) > 0 or len(simkl_episodes) > 0):
                    logger.warning("Skipping bidirectional sync (Simkl -> Plex): Plex returned 0 items while Simkl has %d. "
                                   "This likely indicates a Plex connection issue.",
                                   len(simkl_movies) + len(simkl_episodes))
                else:
                    movies_to_add_plex = set(simkl_movies) - set(plex_movies)
                    # Secondary lookup by (show_title, code) for Plex episodes
                    plex_episodes_by_show_code = set()
                    for _guid, _ep_info in plex_episodes.items():
                        plex_episodes_by_show_code.add((_ep_info["show"].lower(), _ep_info["code"].upper()))
                    episodes_to_add_plex = set()
                    for e_key in set(simkl_episodes):
                        if e_key in set(plex_episodes):
                            continue
                        ep_info = simkl_episodes[e_key]
                        show_code = (ep_info[0].lower(), ep_info[1].upper())
                        if show_code in plex_episodes_by_show_code:
                            continue
                        episodes_to_add_plex.add(e_key)
                    logger.info(
                        "Found %d movies and %d episodes to add to Plex",
                        len(movies_to_add_plex),
                        len(episodes_to_add_plex),
                    )
                    movies_to_add_plex_fmt = {
                        (simkl_movies[m][0], simkl_movies[m][1], m)
                        for m in movies_to_add_plex
                    }
                    episodes_to_add_plex_fmt = {
                        (simkl_episodes[e][0], simkl_episodes[e][1], e)
                        for e in episodes_to_add_plex
                    }
                    if movies_to_add_plex_fmt or episodes_to_add_plex_fmt:
                        if stop_event.is_set():
                            logger.info("Sync cancelled")
                            return
                        update_plex(sync_plex, movies_to_add_plex_fmt, episodes_to_add_plex_fmt)
            elif HISTORY_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX):
                movies_to_add_plex = set(simkl_movies) - set(plex_movies)
                # Secondary lookup by (show_title, code) for Plex episodes
                plex_episodes_by_show_code_log = set()
                for _guid, _ep_info in plex_episodes.items():
                    plex_episodes_by_show_code_log.add((_ep_info["show"].lower(), _ep_info["code"].upper()))
                episodes_to_add_plex = set()
                for e_key in set(simkl_episodes):
                    if e_key in set(plex_episodes):
                        continue
                    ep_info = simkl_episodes[e_key]
                    show_code = (ep_info[0].lower(), ep_info[1].upper())
                    if show_code in plex_episodes_by_show_code_log:
                        continue
                    episodes_to_add_plex.add(e_key)
                if movies_to_add_plex or episodes_to_add_plex:
                    logger.info("Skipping bidirectional sync for managed user %s: %d movies and %d episodes would have been synced from Simkl to Plex", 
                               selected_user["username"], len(movies_to_add_plex), len(episodes_to_add_plex))



    except Exception as exc:  # noqa: BLE001
        logger.error("Error during sync: %s", exc)
        import traceback
        logger.debug("Sync error traceback: %s", traceback.format_exc())

    # Ratings sync
    if SYNC_RATINGS and RATINGS_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_PLEX_TO_SERVICE):
        if SYNC_PROVIDER == "trakt":
            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            try:
                sync_ratings(sync_plex, headers)
            except Exception as exc:
                logger.error("Ratings sync (Plex -> Trakt) failed: %s", exc)
        elif SYNC_PROVIDER == "simkl":
            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            try:
                sync_simkl_ratings(sync_plex, headers)
            except Exception as exc:
                logger.error("Ratings sync (Plex -> Simkl) failed: %s", exc)

    if SYNC_RATINGS and RATINGS_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX):
        if SYNC_PROVIDER == "trakt" and selected_user.get("is_owner", False):
            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            try:
                apply_trakt_ratings(sync_plex, headers)
            except Exception as exc:
                logger.error("Ratings sync (Trakt -> Plex) failed: %s", exc)
        elif SYNC_PROVIDER == "simkl" and selected_user.get("is_owner", False):
            if stop_event.is_set():
                logger.info("Sync cancelled")
                return
            try:
                apply_simkl_ratings(sync_plex, headers)
            except Exception as exc:
                logger.error("Ratings sync (Simkl -> Plex) failed: %s", exc)

    if SYNC_WATCHLISTS and SYNC_PROVIDER == "trakt":
        if stop_event.is_set():
            logger.info("Sync cancelled")
            return
        # Ensure these variables are defined, initialize as empty sets if not
        try:
            plex_history_guids = plex_movie_guids | plex_episode_guids
            trakt_history_guids = trakt_movie_guids | trakt_episode_guids
        except NameError:
            # Variables not defined (e.g., if only watchlist sync is enabled)
            logger.debug("History variables not defined, using empty sets for watchlist sync")
            plex_history_guids = set()
            trakt_history_guids = set()
        
        try:
            sync_watchlists_only(
                sync_plex,
                headers,
                plex_history_guids,
                trakt_history_guids,
            )
        except Exception as exc:
            logger.error("Watchlist sync failed: %s", exc)

        mirror_trakt_watchlist_to_simkl(headers)
    elif SYNC_WATCHLISTS and SYNC_PROVIDER == "simkl":
        logger.warning("Watchlist sync with Simkl is not yet supported.")

    if SYNC_COLLECTION and COLLECTION_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_PLEX_TO_SERVICE):
        if stop_event.is_set():
            logger.info("Sync cancelled")
            return
        try:
            sync_collection(sync_plex, headers)
        except Exception as exc:
            logger.error("Collection sync failed: %s", exc)

    if SYNC_COLLECTION and COLLECTION_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX):
        logger.warning("Collection import from Trakt is not implemented.")

    if SYNC_LIKED_LISTS and SYNC_PROVIDER == "trakt":
        if stop_event.is_set():
            logger.info("Sync cancelled")
            return
        try:
            if LISTS_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_SERVICE_TO_PLEX):
                logger.info("Starting liked lists sync (Trakt -> Plex)...")
                sync_liked_lists(sync_plex, headers)
                logger.info("Liked lists sync (Trakt -> Plex) completed.")
            if LISTS_SYNC_DIRECTION in (DIRECTION_BOTH, DIRECTION_PLEX_TO_SERVICE):
                logger.info("Starting collections sync (Plex -> Trakt)...")
                sync_collections_to_trakt(sync_plex, headers)
                logger.info("Collections sync (Plex -> Trakt) completed.")
        except TraktAccountLimitError as exc:
            logger.error("Liked-lists sync skipped: %s", exc)
        except Exception as exc:
            logger.error("Liked-lists sync failed: %s", exc)
    elif SYNC_LIKED_LISTS and SYNC_PROVIDER == "simkl":
        logger.warning("Liked lists sync with Simkl is not yet supported.")

    if SYNC_WATCHED:
        save_last_plex_sync(datetime.utcnow().isoformat() + "Z")
    logger.info("Sync finished.")


def fetch_trakt_history_full(headers) -> list:
    """Return full watch history from Trakt."""
    all_items = []
    page = 1
    while True:
        resp = trakt_request(
            "GET",
            "/sync/history",
            headers,
            params={"page": page, "limit": 100},
        )
        data = resp.json()
        if not data:
            break
        all_items.extend(data)
        page += 1
    return all_items


def fetch_trakt_ratings(headers) -> list:
    """Return all ratings from Trakt."""
    all_items = []
    page = 1
    while True:
        resp = trakt_request(
            "GET",
            "/sync/ratings",
            headers,
            params={"page": page, "limit": 100},
        )
        data = resp.json()
        if not data:
            break
        all_items.extend(data)
        page += 1
    return all_items


def fetch_trakt_watchlist(headers) -> dict:
    """Return movies and shows from the Trakt watchlist."""
    movies = trakt_request("GET", "/sync/watchlist/movies", headers).json()
    shows = trakt_request("GET", "/sync/watchlist/shows", headers).json()
    return {"movies": movies, "shows": shows}


def restore_backup(headers, data: dict) -> None:
    """Restore Trakt data from backup dict."""
    history = data.get("history", [])
    movies = []
    episodes = []
    for item in history:
        if item.get("type") == "movie":
            m = item.get("movie", {})
            ids = m.get("ids", {})
            if ids:
                obj = {"ids": ids}
                if item.get("watched_at"):
                    obj["watched_at"] = item["watched_at"]
                if m.get("title"):
                    obj["title"] = m.get("title")
                if m.get("year"):
                    obj["year"] = m.get("year")
                movies.append(obj)
        elif item.get("type") == "episode":
            ep = item.get("episode", {})
            ids = ep.get("ids", {})
            if ids:
                obj = {
                    "ids": ids,
                    "season": ep.get("season"),
                    "number": ep.get("number"),
                }
                if item.get("watched_at"):
                    obj["watched_at"] = item["watched_at"]
                show = item.get("show", {})
                if show.get("ids"):
                    obj["show"] = {"ids": show.get("ids")}
                episodes.append(obj)
    payload = {}
    if movies:
        payload["movies"] = movies
    if episodes:
        payload["episodes"] = episodes
    if payload:
        trakt_request("POST", "/sync/history", headers, json=payload)

    ratings = data.get("ratings", [])
    r_movies, r_shows, r_episodes, r_seasons = [], [], [], []
    for item in ratings:
        typ = item.get("type")
        ids = item.get(typ, {}).get("ids", {}) if typ else {}
        if not ids:
            continue
        obj = {"ids": ids, "rating": item.get("rating")}
        if item.get("rated_at"):
            obj["rated_at"] = item["rated_at"]
        if typ == "movie":
            r_movies.append(obj)
        elif typ == "show":
            r_shows.append(obj)
        elif typ == "season":
            r_seasons.append(obj)
        elif typ == "episode":
            r_episodes.append(obj)
    payload = {}
    if r_movies:
        payload["movies"] = r_movies
    if r_shows:
        payload["shows"] = r_shows
    if r_seasons:
        payload["seasons"] = r_seasons
    if r_episodes:
        payload["episodes"] = r_episodes
    if payload:
        trakt_request("POST", "/sync/ratings", headers, json=payload)

    watchlist = data.get("watchlist", {})
    wl_movies = []
    for it in watchlist.get("movies", []):
        m = it.get("movie", {})
        ids = m.get("ids", {})
        if ids:
            wl_movies.append({"ids": ids})
    wl_shows = []
    for it in watchlist.get("shows", []):
        s = it.get("show", {}) if "show" in it else it.get("movie", {})
        ids = s.get("ids", {})
        if ids:
            wl_shows.append({"ids": ids})
    payload = {}
    if wl_movies:
        payload["movies"] = wl_movies
    if wl_shows:
        payload["shows"] = wl_shows
    if payload:
        trakt_request("POST", "/sync/watchlist", headers, json=payload)


# --------------------------------------------------------------------------- #
# FLASK ROUTES
# --------------------------------------------------------------------------- #

# ---- Login / Authentication Routes ----
@app.route("/login", methods=["GET", "POST"])
def login_page():
    """Display login page and handle authentication."""
    if session.get("authenticated"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _is_rate_limited(ip):
            error = "Too many failed attempts. Please wait 5 minutes."
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if verify_credentials(username, password):
                session.permanent = True
                session["authenticated"] = True
                session["auth_user"] = username
                logger.info("Successful login from %s", ip)
                return redirect(url_for("index"))
            else:
                _record_login_attempt(ip)
                error = "Invalid username or password."
                logger.warning("Failed login attempt from %s for user '%s'", ip, username)

    return render_template("login.html", error=error)


@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    """Change the user password. Requires current username and double confirmation."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not username or not new_password or not confirm_password:
        return jsonify({"success": False, "error": "All fields are required."}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "error": "Passwords do not match."}), 400

    if len(new_password) < 4:
        return jsonify({"success": False, "error": "Password must be at least 4 characters."}), 400

    creds = load_credentials()
    stored_user = creds.get("username", "")
    if not hmac.compare_digest(username.lower(), stored_user.lower()):
        return jsonify({"success": False, "error": "Invalid username."}), 403

    creds["password_hash"] = generate_password_hash(
        new_password, method="pbkdf2:sha256", salt_length=16
    )
    save_credentials(creds)
    logger.info("Password changed successfully for user '%s'", username)
    return jsonify({"success": True, "message": "Password changed successfully."})


@app.route("/api/disconnect_service", methods=["POST"])
@login_required
def disconnect_service():
    """Disconnect from a specific service (plex, trakt, simkl) and wipe its tokens."""
    data = request.get_json(silent=True) or {}
    service = data.get("service", "").lower()

    if service == "plex":
        # Clear Plex tokens from auth file
        auth = load_auth()
        auth.pop("plex", None)
        save_auth(auth)
        # Clear env vars
        os.environ.pop("PLEX_TOKEN", None)
        os.environ.pop("PLEX_BASE_URL", None)
        # Clear session credentials
        clear_session_credentials()
        # Clear Flask session Plex data
        session.pop("plex_token", None)
        session.pop("plex_baseurl", None)
        # Reset global Plex variables
        global plex, plex_account, _plex_connection_ok
        plex = None
        plex_account = None
        _plex_connection_ok = False
        # Clear selected user
        if os.path.exists(SELECTED_USER_FILE):
            os.remove(SELECTED_USER_FILE)
        logger.info("Disconnected from Plex and wiped all Plex tokens")
        return jsonify({"success": True, "message": "Disconnected from Plex."})

    elif service == "trakt":
        # Clear Trakt tokens from auth file
        auth = load_auth()
        auth.pop("trakt", None)
        save_auth(auth)
        # Clear env vars
        os.environ.pop("TRAKT_ACCESS_TOKEN", None)
        os.environ.pop("TRAKT_REFRESH_TOKEN", None)
        os.environ.pop("TRAKT_EXPIRES_AT", None)
        # Reset provider if it was trakt
        if SYNC_PROVIDER == "trakt":
            save_provider("none")
        logger.info("Disconnected from Trakt and wiped all Trakt tokens")
        return jsonify({"success": True, "message": "Disconnected from Trakt."})

    elif service == "simkl":
        # Clear Simkl tokens from auth file
        auth = load_auth()
        auth.pop("simkl", None)
        save_auth(auth)
        # Clear env vars
        os.environ.pop("SIMKL_ACCESS_TOKEN", None)
        # Reset provider if it was simkl
        if SYNC_PROVIDER == "simkl":
            save_provider("none")
        logger.info("Disconnected from Simkl and wiped all Simkl tokens")
        return jsonify({"success": True, "message": "Disconnected from Simkl."})

    return jsonify({"success": False, "error": "Unknown service."}), 400


@app.route("/api/wipe_all_data", methods=["POST"])
@login_required
def wipe_all_data():
    """Wipe ALL residual data: tokens, state, config (except credentials)."""
    try:
        # Clear auth file (tokens for all services)
        auth_data = {}
        save_auth(auth_data)

        # Clear env vars for all services
        for var in ["PLEX_TOKEN", "PLEX_BASE_URL", "TRAKT_ACCESS_TOKEN",
                     "TRAKT_REFRESH_TOKEN", "TRAKT_EXPIRES_AT", "SIMKL_ACCESS_TOKEN"]:
            os.environ.pop(var, None)

        # Clear session credentials
        clear_session_credentials()

        # Reset global Plex variables
        global plex, plex_account, _plex_connection_ok
        plex = None
        plex_account = None
        _plex_connection_ok = False

        # Clear state files
        for fname in os.listdir(STATE_DIR):
            fpath = os.path.join(STATE_DIR, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)
                logger.info("Removed state file: %s", fpath)

        # Clear config files except credentials.json and settings.json
        for fname in os.listdir(CONFIG_DIR):
            fpath = os.path.join(CONFIG_DIR, fname)
            if os.path.isfile(fpath) and fname not in ("credentials.json", "settings.json"):
                os.remove(fpath)
                logger.info("Removed config file: %s", fpath)

        # Reset provider
        save_provider("none")

        # Stop scheduler
        stop_scheduler()

        logger.info("All residual data wiped successfully")
        return jsonify({"success": True, "message": "All data wiped successfully. Tokens, state and identifiable data have been removed."})
    except Exception as exc:
        logger.error("Failed to wipe data: %s", exc)
        return jsonify({"success": False, "error": str(exc)}), 500


# --------------------------------------------------------------------------- #
# REDIRECT URI MANAGEMENT API
# --------------------------------------------------------------------------- #
@app.route("/api/redirect_uris", methods=["GET"])
@login_required
def get_redirect_uris():
    """Return saved redirect URIs and the currently active one for each service."""
    load_settings()
    # Build the default URI for each service using the current request context
    defaults = {
        "trakt": request.url_root.rstrip("/") + "/oauth/trakt",
        "simkl": request.url_root.rstrip("/") + "/oauth/simkl",
    }
    result = {}
    for svc in ("trakt", "simkl"):
        saved = list(REDIRECT_URIS.get(svc, {}).get("saved", []))
        active = REDIRECT_URIS.get(svc, {}).get("active", "")
        # Ensure the default URI is always present in the list
        if defaults[svc] not in saved:
            saved.insert(0, defaults[svc])
        # Also include the env var value if set and not already listed
        env_uri = os.environ.get(f"{svc.upper()}_REDIRECT_URI", "")
        if env_uri and env_uri not in saved:
            saved.insert(0, env_uri)
        result[svc] = {"saved": saved, "active": active, "default": defaults[svc]}
    return jsonify(result)


@app.route("/api/redirect_uris", methods=["POST"])
@login_required
def save_redirect_uris_api():
    """Save a new redirect URI or set the active one for a service.

    Body JSON: { "service": "trakt"|"simkl", "action": "add"|"remove"|"set_active", "uri": "..." }
    """
    global REDIRECT_URIS
    data = request.get_json(silent=True) or {}
    service = (data.get("service") or "").lower()
    action = data.get("action", "")
    uri = (data.get("uri") or "").strip()

    if service not in ("trakt", "simkl"):
        return jsonify({"success": False, "error": "Invalid service. Use 'trakt' or 'simkl'."}), 400
    if not uri:
        return jsonify({"success": False, "error": "URI is required."}), 400

    saved = REDIRECT_URIS[service].get("saved", [])

    if action == "add":
        if uri in saved:
            return jsonify({"success": False, "error": "URI already exists."}), 409
        saved.append(uri)
        REDIRECT_URIS[service]["saved"] = saved
        save_settings()
        logger.info("Added redirect URI for %s: %s", service, uri)
        return jsonify({"success": True, "message": f"URI added for {service}."})

    elif action == "remove":
        if uri in saved:
            saved.remove(uri)
            REDIRECT_URIS[service]["saved"] = saved
            # If removing the active URI, clear active selection
            if REDIRECT_URIS[service].get("active") == uri:
                REDIRECT_URIS[service]["active"] = ""
            save_settings()
            logger.info("Removed redirect URI for %s: %s", service, uri)
            return jsonify({"success": True, "message": f"URI removed for {service}."})
        return jsonify({"success": False, "error": "URI not found."}), 404

    elif action == "set_active":
        REDIRECT_URIS[service]["active"] = uri
        # Also ensure it's saved
        if uri not in saved:
            saved.append(uri)
            REDIRECT_URIS[service]["saved"] = saved
        save_settings()
        logger.info("Set active redirect URI for %s: %s", service, uri)
        return jsonify({"success": True, "message": f"Active URI set for {service}."})

    return jsonify({"success": False, "error": "Invalid action. Use 'add', 'remove', or 'set_active'."}), 400


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    global SYNC_INTERVAL_MINUTES, SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS, SYNC_WATCHLISTS, LIVE_SYNC
    global HISTORY_SYNC_DIRECTION, LISTS_SYNC_DIRECTION, WATCHLISTS_SYNC_DIRECTION, RATINGS_SYNC_DIRECTION, COLLECTION_SYNC_DIRECTION

    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()
    load_settings()

    # Change interval and start sync when requested
    if request.method == "POST":
        minutes = int(request.form.get("minutes", 60))
        SYNC_INTERVAL_MINUTES = minutes
        SYNC_COLLECTION = request.form.get("collection") is not None
        SYNC_RATINGS = request.form.get("ratings") is not None
        SYNC_WATCHED = request.form.get("watched") is not None
        SYNC_LIKED_LISTS = request.form.get("liked_lists") is not None
        SYNC_WATCHLISTS = request.form.get("watchlists") is not None
        LIVE_SYNC = request.form.get("live_sync") is not None

        HISTORY_SYNC_DIRECTION = request.form.get("history_direction", DIRECTION_BOTH)
        LISTS_SYNC_DIRECTION = request.form.get("lists_direction", DIRECTION_BOTH)
        WATCHLISTS_SYNC_DIRECTION = request.form.get("watchlists_direction", DIRECTION_BOTH)
        RATINGS_SYNC_DIRECTION = request.form.get("ratings_direction", DIRECTION_BOTH)
        COLLECTION_SYNC_DIRECTION = request.form.get("collection_direction", DIRECTION_BOTH)

        # Check if a managed user is selected and restrict options
        selected_user = load_selected_user()
        if selected_user and not selected_user.get("is_owner", False):
            # For managed users force Plex -> service direction and disable restricted options
            SYNC_COLLECTION = False
            SYNC_LIKED_LISTS = False
            SYNC_WATCHLISTS = False
            HISTORY_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
            LISTS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
            WATCHLISTS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
            RATINGS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
            COLLECTION_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
            logger.info(
                "Restricted sync options disabled for managed user: %s",
                selected_user.get("username", "Unknown"),
            )

        if SYNC_PROVIDER == "simkl":
            SYNC_COLLECTION = False
            SYNC_LIKED_LISTS = False
            SYNC_WATCHLISTS = False

        # Persist final settings to disk after applying restrictions
        save_settings()
        
        # Only start scheduler when manually requested from sync tab
        # Check if a user is selected first
        selected_user = load_selected_user()
        if not selected_user:
            return redirect(
                url_for("index", message="Please select a user first in the Users tab before starting sync!", mtype="error")
            )
        
        start_scheduler()
        
        # Trigger an immediate sync by updating the next run time
        job = scheduler.get_job("sync_job")
        if job:
            scheduler.modify_job("sync_job", next_run_time=datetime.now())
        return redirect(
            url_for("index", message=f"Sync started successfully for user: {selected_user['username']} ({selected_user['role']})!", mtype="success")
        )

    message = request.args.get("message")
    mtype = request.args.get("mtype", "success") if message else None
    next_run = None
    job = scheduler.get_job("sync_job")
    if job:
        next_run = job.next_run_time
    
    selected_user = load_selected_user()
    display_collection = SYNC_COLLECTION
    display_ratings = SYNC_RATINGS
    display_liked_lists = SYNC_LIKED_LISTS
    display_watchlists = SYNC_WATCHLISTS
    display_live_sync = LIVE_SYNC

    if SYNC_PROVIDER == "simkl":
        display_collection = False
        display_liked_lists = False
        display_watchlists = False

    if selected_user and not selected_user.get("is_owner", False):
        # Disable restricted options in the UI for managed users
        display_collection = False
        display_liked_lists = False
        display_watchlists = False
    
    return render_template(
        "index.html",
        minutes=SYNC_INTERVAL_MINUTES,
        collection=display_collection,
        ratings=display_ratings,
        watched=SYNC_WATCHED,
        liked_lists=display_liked_lists,
        watchlists=display_watchlists,
        live_sync=display_live_sync,
        history_direction=HISTORY_SYNC_DIRECTION,
        lists_direction=LISTS_SYNC_DIRECTION,
        watchlists_direction=WATCHLISTS_SYNC_DIRECTION,
        ratings_direction=RATINGS_SYNC_DIRECTION,
        collection_direction=COLLECTION_SYNC_DIRECTION,
        provider=SYNC_PROVIDER,
        message=message,
        mtype=mtype,
        next_run=next_run,
    )


@app.route("/sync_once", methods=["POST"])
@login_required
def sync_once():
    global SYNC_INTERVAL_MINUTES, SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS, SYNC_WATCHLISTS, LIVE_SYNC
    global HISTORY_SYNC_DIRECTION, LISTS_SYNC_DIRECTION, WATCHLISTS_SYNC_DIRECTION, RATINGS_SYNC_DIRECTION, COLLECTION_SYNC_DIRECTION

    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()
    load_settings()

    minutes = int(request.form.get("minutes", 60))
    SYNC_INTERVAL_MINUTES = minutes
    SYNC_COLLECTION = request.form.get("collection") is not None
    SYNC_RATINGS = request.form.get("ratings") is not None
    SYNC_WATCHED = request.form.get("watched") is not None
    SYNC_LIKED_LISTS = request.form.get("liked_lists") is not None
    SYNC_WATCHLISTS = request.form.get("watchlists") is not None
    LIVE_SYNC = request.form.get("live_sync") is not None

    HISTORY_SYNC_DIRECTION = request.form.get("history_direction", DIRECTION_BOTH)
    LISTS_SYNC_DIRECTION = request.form.get("lists_direction", DIRECTION_BOTH)
    WATCHLISTS_SYNC_DIRECTION = request.form.get("watchlists_direction", DIRECTION_BOTH)
    RATINGS_SYNC_DIRECTION = request.form.get("ratings_direction", DIRECTION_BOTH)
    COLLECTION_SYNC_DIRECTION = request.form.get("collection_direction", DIRECTION_BOTH)

    selected_user = load_selected_user()
    if selected_user and not selected_user.get("is_owner", False):
        SYNC_COLLECTION = False
        SYNC_LIKED_LISTS = False
        SYNC_WATCHLISTS = False
        HISTORY_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
        LISTS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
        WATCHLISTS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
        RATINGS_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
        COLLECTION_SYNC_DIRECTION = DIRECTION_PLEX_TO_SERVICE
        logger.info(
            "Restricted sync options disabled for managed user: %s",
            selected_user.get("username", "Unknown"),
        )

    if SYNC_PROVIDER == "simkl":
        SYNC_COLLECTION = False
        SYNC_LIKED_LISTS = False
        SYNC_WATCHLISTS = False

    save_settings()

    if not selected_user:
        return redirect(
            url_for("index", message="Please select a user first in the Users tab before starting sync!", mtype="error")
        )

    stop_event.clear()
    only_watchlist = SYNC_WATCHLISTS and not any(
        [SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS]
    )
    if only_watchlist:
        Thread(target=sync_watchlists_only).start()
    else:
        Thread(target=sync).start()

    return redirect(
        url_for(
            "index",
            message=f"One-time sync started successfully for user: {selected_user['username']} ({selected_user['role']})!",
            mtype="success",
        )
    )


@app.route("/oauth")
@login_required
def oauth_index():
    """Landing page for OAuth callbacks."""
    return render_template("oauth.html", service=None, code=None)


@app.route("/oauth/<service>")
@login_required
def oauth_callback(service: str):
    """Handle OAuth callback: auto-exchange code for tokens when possible."""
    service = service.lower()
    if service not in {"trakt", "simkl"}:
        return redirect(url_for("oauth_index"))
    code = request.args.get("code", "")

    # Auto-exchange the code for tokens immediately
    if code:
        logger.info("Received OAuth callback for %s with authorization code", service)
        if service == "trakt":
            result = exchange_code_for_tokens(code)
            if result:
                if SYNC_PROVIDER == "none":
                    save_provider("trakt")
                logger.info("Trakt authorization completed successfully via OAuth callback")
                return redirect(url_for("config_page"))
            else:
                logger.warning("Auto-exchange failed for Trakt, showing code for manual entry")
        elif service == "simkl":
            result = exchange_code_for_simkl_tokens(code)
            if result:
                if SYNC_PROVIDER == "none":
                    save_provider("simkl")
                logger.info("Simkl authorization completed successfully via OAuth callback")
                return redirect(url_for("config_page"))
            else:
                logger.warning("Auto-exchange failed for Simkl, showing code for manual entry")

    return render_template(
        "oauth.html",
        service=service.capitalize(),
        code=code,
    )


@app.route("/trakt")
@login_required
def trakt_callback():
    code = request.args.get("code", "")
    return redirect(url_for("oauth_callback", service="trakt", code=code))


@app.route("/simkl")
@login_required
def simkl_callback():
    code = request.args.get("code", "")
    return redirect(url_for("oauth_callback", service="simkl", code=code))


@app.route("/config", methods=["GET", "POST"])
@login_required
def config_page():
    """Display configuration status for Trakt and Simkl."""
    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()
    load_settings()
    if request.method == "POST":
        provider = request.form.get("provider", "none")
        save_provider(provider)
        if provider == "none":
            stop_scheduler()
        # Removed automatic scheduler start - only manual start from sync tab
        return redirect(url_for("config_page"))
    trakt_configured = bool(os.environ.get("TRAKT_ACCESS_TOKEN"))
    simkl_configured = bool(os.environ.get("SIMKL_ACCESS_TOKEN"))
    return render_template(
        "config.html",
        trakt_configured=trakt_configured,
        simkl_configured=simkl_configured,
        provider=SYNC_PROVIDER,
    )


@app.route("/settings")
@login_required
def settings_page():
    """Display settings page with security and redirect URI management."""
    load_settings()
    return render_template(
        "settings.html",
        trakt_redirect_uri=get_trakt_redirect_uri(),
        simkl_redirect_uri=get_simkl_redirect_uri(),
    )


@app.route("/authorize/<service>", methods=["GET", "POST"])
@login_required
def authorize_service(service: str):
    """Handle authorization for Trakt or Simkl."""
    service = service.lower()
    prefill = request.args.get("code", "").strip()
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if service == "trakt" and code and exchange_code_for_tokens(code):
            if SYNC_PROVIDER == "none":
                save_provider("trakt")
            # Removed automatic scheduler start - only manual start from sync tab
            return redirect(url_for("config_page"))
        if service == "simkl" and code and exchange_code_for_simkl_tokens(code):
            if SYNC_PROVIDER == "none":
                save_provider("simkl")
            # Removed automatic scheduler start - only manual start from sync tab
            return redirect(url_for("config_page"))

    if service == "trakt":
        auth_url = (
            "https://trakt.tv/oauth/authorize"
            f"?response_type=code&client_id={os.environ.get('TRAKT_CLIENT_ID')}"
            f"&redirect_uri={get_trakt_redirect_uri()}"
        )
    elif service == "simkl":
        auth_url = (
            "https://simkl.com/oauth/authorize"
            f"?response_type=code&client_id={os.environ.get('SIMKL_CLIENT_ID')}"
            f"&redirect_uri={get_simkl_redirect_uri()}"
        )
    else:
        return redirect(url_for("config_page"))

    return render_template(
        "authorize.html",
        auth_url=auth_url,
        service=service.capitalize(),
        code=prefill,
    )


@app.route("/clear/<service>", methods=["POST"])
@login_required
def clear_service(service: str):
    """Remove stored tokens for the given service."""
    service = service.lower()
    if service == "trakt":
        os.environ.pop("TRAKT_ACCESS_TOKEN", None)
        os.environ.pop("TRAKT_REFRESH_TOKEN", None)
        auth = load_auth()
        auth.pop("trakt", None)
        save_auth(auth)
        logger.info("Removed Trakt tokens")
        if SYNC_PROVIDER == "trakt":
            save_provider("none")
    elif service == "simkl":
        os.environ.pop("SIMKL_ACCESS_TOKEN", None)
        auth = load_auth()
        auth.pop("simkl", None)
        save_auth(auth)
        logger.info("Removed Simkl token")
        if SYNC_PROVIDER == "simkl":
            save_provider("none")
    else:
        return jsonify({"success": False, "error": "Unknown service"})
    return redirect(url_for("config_page"))


@app.route("/stop", methods=["POST"])
@login_required
def stop():
    stop_scheduler()
    return redirect(
        url_for("index", message="Sync stopped successfully!", mtype="stopped")
    )



@app.route("/backup")
@login_required
def backup_page():
    message = request.args.get("message")
    mtype = request.args.get("mtype", "success") if message else None
    return render_template("backup.html", message=message, mtype=mtype)


@app.route("/backup/download")
@login_required
def download_backup():
    load_trakt_tokens()
    trakt_token = os.environ.get("TRAKT_ACCESS_TOKEN")
    trakt_client_id = os.environ.get("TRAKT_CLIENT_ID")
    if not trakt_token or not trakt_client_id:
        return redirect(
            url_for("backup_page", message="Missing Trakt credentials", mtype="error")
        )
    headers = {
        "Authorization": f"Bearer {trakt_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "trakt-api-version": "2",
        "trakt-api-key": trakt_client_id,
    }
    data = {
        "history": fetch_trakt_history_full(headers),
        "ratings": fetch_trakt_ratings(headers),
        "watchlist": fetch_trakt_watchlist(headers),
    }
    tmp_path = "trakt_backup.json"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return send_file(tmp_path, as_attachment=True, download_name="trakt_backup.json")


@app.route("/backup/restore", methods=["POST"])
@login_required
def restore_backup_route():
    load_trakt_tokens()
    trakt_token = os.environ.get("TRAKT_ACCESS_TOKEN")
    trakt_client_id = os.environ.get("TRAKT_CLIENT_ID")
    if not trakt_token or not trakt_client_id:
        return redirect(
            url_for("backup_page", message="Missing Trakt credentials", mtype="error")
        )
    headers = {
        "Authorization": f"Bearer {trakt_token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "trakt-api-version": "2",
        "trakt-api-key": trakt_client_id,
    }
    file = request.files.get("backup")
    if not file:
        return redirect(
            url_for("backup_page", message="No file uploaded", mtype="error")
        )
    try:
        data = json.load(file)
    except Exception:
        return redirect(url_for("backup_page", message="Invalid JSON", mtype="error"))
    try:
        restore_backup(headers, data)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to restore backup: %s", exc)
        return redirect(url_for("backup_page", message="Restore failed", mtype="error"))
    return redirect(url_for("backup_page", message="Backup restored", mtype="success"))


@app.route("/migration", methods=["GET", "POST"])
@app.route("/service_sync", methods=["GET", "POST"])
@login_required
def migration_page():
    """Synchronize history between Trakt and Simkl."""
    load_trakt_tokens()
    load_simkl_tokens()

    message = None
    mtype = "success"

    if request.method == "POST":
        direction = request.form.get("direction")

        trakt_token = os.environ.get("TRAKT_ACCESS_TOKEN")
        trakt_client_id = os.environ.get("TRAKT_CLIENT_ID")
        simkl_token = os.environ.get("SIMKL_ACCESS_TOKEN")
        simkl_client_id = os.environ.get("SIMKL_CLIENT_ID")

        if direction == "trakt_to_simkl":
            if not (trakt_token and trakt_client_id and simkl_token and simkl_client_id):
                message = "Missing Trakt or Simkl credentials"
                mtype = "error"
            else:
                trakt_headers = {
                    "Authorization": f"Bearer {trakt_token}",
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "trakt-api-version": "2",
                    "trakt-api-key": trakt_client_id,
                }
                simkl_headers = {
                    "Authorization": f"Bearer {simkl_token}",
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "simkl-api-key": simkl_client_id,
                }

                from migration_utils import trakt_to_simkl

                def run_trakt_to_simkl() -> None:
                    try:
                        trakt_to_simkl(trakt_headers, simkl_headers)
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Service sync failed: %s", exc)

                Thread(target=run_trakt_to_simkl).start()
                message = "Migration started"

        elif direction == "simkl_to_trakt":
            if not (trakt_token and trakt_client_id and simkl_token and simkl_client_id):
                message = "Missing Trakt or Simkl credentials"
                mtype = "error"
            else:
                trakt_headers = {
                    "Authorization": f"Bearer {trakt_token}",
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "trakt-api-version": "2",
                    "trakt-api-key": trakt_client_id,
                }
                simkl_headers = {
                    "Authorization": f"Bearer {simkl_token}",
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                    "simkl-api-key": simkl_client_id,
                }

                from migration_utils import simkl_to_trakt

                def run_simkl_to_trakt() -> None:
                    try:
                        simkl_to_trakt(simkl_headers, trakt_headers)
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Service sync failed: %s", exc)

                Thread(target=run_simkl_to_trakt).start()
                message = "Migration started"

        else:
            message = "Invalid sync direction"
            mtype = "error"

    return render_template("migration.html", message=message, mtype=mtype)


@app.route("/webhook", methods=["POST"])
def plex_webhook():
    """Handle Plex webhook events for live synchronization."""
    if LIVE_SYNC:
        # Trigger a one-off sync immediately
        stop_event.clear()

        if SYNC_PROVIDER == "simkl":
            client_id = os.environ.get("SIMKL_CLIENT_ID")
            token = os.environ.get("SIMKL_ACCESS_TOKEN")
            if client_id and token:
                url = (
                    f"https://api.simkl.com/sync/plex/webhook?client_id={client_id}&token={token}"
                )
                try:
                    requests.post(
                        url,
                        data=request.data,
                        headers={
                            "Content-Type": request.content_type
                            or "application/json"
                        },
                        timeout=10,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to forward webhook to Simkl: %s", exc)
            else:
                logger.warning(
                    "Missing Simkl client ID or access token; cannot forward webhook."
                )

        only_watchlist = SYNC_WATCHLISTS and not any(
            [SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS]
        )
        job_func = sync_watchlists_only if only_watchlist else sync
        scheduler.add_job(job_func, "date", run_date=datetime.now())
    return "", 204


@app.route("/users")
@login_required
def users_page():
    """Display Plex users and optional play history counts."""
    # No intentar conectar automáticamente - la página manejará la autenticación
    # Esta página ahora usa la interfaz interactiva para autenticación
    
    # Si hay credenciales configuradas, intentar obtener información automáticamente
    email = os.environ.get("PLEX_EMAIL")
    password = os.environ.get("PLEX_PASSWORD")
    
    owner = None
    users = []
    watch_counts = None
    
    if email and password:
        # Solo si hay credenciales preconfiguradas, intentar conexión automática
        try:
            plex_server = get_plex_server()
            account = get_plex_account()
            
            if plex_server and account:
                # Obtener información del owner desde la cuenta myPlex
                owner = {
                    "id": account.id,
                    "username": account.username,
                    "role": "owner",
                    "selectable": True,
                    "is_owner": True,
                }

                # Obtener usuarios gestionados usando el nuevo esquema
                try:
                    for user in account.users():
                        logger.debug("MyPlexUser: ID=%s, username=%s, title=%s, home=%s, friend=%s", 
                                    getattr(user, 'id', 'N/A'), 
                                    getattr(user, 'username', 'N/A'), 
                                    getattr(user, 'title', 'N/A'),
                                    getattr(user, 'home', 'N/A'),
                                    getattr(user, 'friend', 'N/A'))
                        
                        # Determinar el rol del usuario correctamente
                        if hasattr(user, 'home') and user.home:
                            role = "managed user"
                            selectable = True  # Los managed users son seleccionables
                        elif hasattr(user, 'friend') and user.friend:
                            role = "friend"
                            selectable = False  # Los friends no son seleccionables para historial
                        else:
                            role = "user"
                            selectable = False
                        
                        users.append({
                            "id": user.id,
                            "username": user.username or user.title,
                            "role": role,
                            "selectable": selectable,
                            "home": getattr(user, 'home', False),
                            "friend": getattr(user, 'friend', False),
                            "is_owner": False,
                        })
                    logger.info("Found %d myPlex users", len(users))
                except Exception as exc:
                    logger.error("Failed to get myPlex users: %s", exc)

                selected_id = request.args.get("user")
                if selected_id:
                    try:
                        uid = int(selected_id)
                    except ValueError:
                        logger.warning("Invalid user ID format: %s", selected_id)
                        uid = None
                    
                    if uid is not None:
                        try:
                            # Usar el nuevo esquema para obtener el historial
                            if uid == account.id:
                                logger.info("Fetching viewing data for owner (account ID: %s)", uid)
                                # Para el owner, obtener historial global
                                watch_counts = get_owner_watch_counts(account)
                            else:
                                logger.info("Fetching viewing data for managed user ID: %s", uid)
                                # Para usuarios gestionados, usar account.user()
                                watch_counts = get_managed_user_watch_counts(account, uid)
                            
                            logger.info("Successfully fetched watch counts for user %s: %d movies, %d episodes", 
                                       uid, watch_counts["movies"], watch_counts["episodes"])
                                
                        except Exception as exc:
                            logger.error("Failed to fetch history for user ID %s: %s", uid, exc)
                            watch_counts = {
                                "movies": 0,
                                "episodes": 0,
                                "total": 0,
                                "error": str(exc)
                            }
        except Exception as exc:
            logger.warning("Auto-authentication failed, will use interactive mode: %s", exc)

    return render_template(
        "users.html",
        owner=owner,
        users=users,
        watch_counts=watch_counts,
        selected_id=int(request.args.get("user")) if request.args.get("user") else None,
    )


@app.route("/api/auth/plex", methods=["POST"])
@login_required
def api_auth_plex():
    """API endpoint for Plex authentication with email/password and optional 2FA."""
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    code = data.get("code")  # 2FA code if provided
    
    if not email or not password:
        return jsonify({"success": False, "error": "Email and password are required"})
    
    try:
        if code:
            # Authentication with 2FA
            account = MyPlexAccount(email, password, code=code)
            logger.info("Successfully authenticated with Plex using 2FA")
        else:
            # Try authentication without 2FA first
            try:
                account = MyPlexAccount(email, password)
                logger.info("Successfully authenticated with Plex (no 2FA required)")
            except Exception as first_exc:
                # Check if the error indicates 2FA is required
                error_str = str(first_exc).lower()
                logger.info("Plex authentication error: %s", error_str)
                
                # Various ways to detect 2FA requirement
                requires_2fa = any([
                    "two-factor" in error_str,
                    "2fa" in error_str,
                    "verification code" in error_str,
                    "code=\"1029\"" in error_str,
                    "1029" in error_str and ("verification" in error_str or "unauthorized" in error_str),
                    ("unauthorized" in error_str and "verification" in error_str),
                    "please enter the verification" in error_str,
                    "enter the verification code" in error_str
                ])
                
                if requires_2fa:
                    logger.info("2FA required - detected from error: %s", error_str)
                    return jsonify({"success": True, "requires_2fa": True})
                else:
                    raise first_exc
        
        # Store authentication in session
        session['plex_email'] = email
        session['plex_password'] = password
        session['plex_token'] = account.authToken  # Store the authentication token
        baseurl = normalize_baseurl(os.environ.get("PLEX_BASEURL"))
        if baseurl:
            session['plex_baseurl'] = baseurl
        if code:
            session['plex_2fa_code'] = code
        session['plex_account_id'] = account.id
        session['plex_username'] = account.username

        # Also save token and base URL for scheduler access
        save_session_credentials(account.authToken, baseurl)
        
        # Update environment variable so scheduler and sync threads can find it
        os.environ["PLEX_TOKEN"] = account.authToken
        
        # Persist Plex token to auth.json so it survives container restarts
        save_plex_token(account.authToken, baseurl or "")
        
        # Reset global Plex variables to force re-authentication with new credentials
        global plex, plex_account, _plex_connection_ok
        plex = None
        plex_account = account
        _plex_connection_ok = False
        
        return jsonify({
            "success": True, 
            "requires_2fa": False,
            "token": f"session_{account.id}",  # Simple session-based token
            "username": account.username,
            "two_factor_enabled": account.twoFactorEnabled
        })
        
    except Exception as exc:
        logger.error("Plex authentication failed: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/plex/servers", methods=["GET"])
@login_required
def api_get_servers():
    """API endpoint to get available Plex servers for authenticated user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"success": False, "error": "Authorization required"})
    
    # Get account from session - try to reuse existing account object
    account_id = session.get('plex_account_id')
    email = session.get('plex_email')
    password = session.get('plex_password')
    code = session.get('plex_2fa_code')
    
    if not email or not password:
        return jsonify({"success": False, "error": "Authentication session expired"})
    
    try:
        # Try to reuse the global plex_account if it exists and matches
        global plex_account
        if plex_account and hasattr(plex_account, 'id') and plex_account.id == account_id:
            account = plex_account
            logger.info("Reusing existing Plex account session")
        else:
            # Only re-authenticate if we don't have a valid session
            # For 2FA users, avoid re-authentication with same code
            if code:
                # Don't re-authenticate with 2FA code as it's single-use
                # Try without code first, this might work if session is still valid
                try:
                    account = MyPlexAccount(email, password)
                    logger.info("Successfully authenticated with Plex (2FA session still valid)")
                except Exception:
                    # If that fails, we need user to re-authenticate
                    logger.error("2FA session expired, user needs to re-authenticate")
                    return jsonify({"success": False, "error": "2FA session expired, please re-authenticate"})
            else:
                account = MyPlexAccount(email, password)
                logger.info("Successfully authenticated with Plex")
            
            # Update global account reference
            plex_account = account
        
        # Get available servers
        resources = account.resources()
        plex_servers = [r for r in resources if r.product == 'Plex Media Server']
        
        servers = []
        for server in plex_servers:
            server_info = {
                "name": server.name,
                "product": server.product,
            }
            
            # Add optional attributes if they exist
            if hasattr(server, 'version'):
                server_info["version"] = server.version
            if hasattr(server, 'owner'):
                server_info["owner"] = server.owner
            if hasattr(server, 'owned'):
                server_info["owned"] = server.owned
            
            servers.append(server_info)
        
        return jsonify({"success": True, "servers": servers})
        
    except Exception as exc:
        logger.error("Failed to get Plex servers: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/plex/users", methods=["GET"])
@login_required
def api_get_users():
    """API endpoint to get users for a specific Plex server."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"success": False, "error": "Authorization required"})
    
    server_name = request.args.get('server')
    user_id = request.args.get('user')
    
    if not server_name:
        return jsonify({"success": False, "error": "Server name required"})
    
    # Get account from session - try to reuse existing account object
    account_id = session.get('plex_account_id')
    email = session.get('plex_email')
    password = session.get('plex_password')
    code = session.get('plex_2fa_code')
    
    if not email or not password:
        return jsonify({"success": False, "error": "Authentication session expired"})
    
    try:
        # Try to reuse the global plex_account if it exists and matches
        global plex_account
        if plex_account and hasattr(plex_account, 'id') and plex_account.id == account_id:
            account = plex_account
            logger.info("Reusing existing Plex account session")
        else:
            # Only re-authenticate if we don't have a valid session
            # For 2FA users, avoid re-authentication with same code
            if code:
                # Don't re-authenticate with 2FA code as it's single-use
                # Try without code first, this might work if session is still valid
                try:
                    account = MyPlexAccount(email, password)
                    logger.info("Successfully authenticated with Plex (2FA session still valid)")
                except Exception:
                    # If that fails, we need user to re-authenticate
                    logger.error("2FA session expired, user needs to re-authenticate")
                    return jsonify({"success": False, "error": "2FA session expired, please re-authenticate"})
            else:
                account = MyPlexAccount(email, password)
                logger.info("Successfully authenticated with Plex")
            
            # Update global account reference
            plex_account = account
        
        server_name = request.args.get('server')
        user_id = request.args.get('user')
        
        # Get owner info
        owner = {
            "id": account.id,
            "username": account.username,
            "role": "owner",
            "selectable": True,
            "is_owner": True,
        }
        
        # Get managed users
        users = []
        for user in account.users():
            # Determine user role and selectability
            if hasattr(user, 'home') and user.home:
                role = "managed user"
                selectable = True
            elif hasattr(user, 'friend') and user.friend:
                role = "friend"
                selectable = False
            else:
                role = "user"
                selectable = False
            
            users.append({
                "id": user.id,
                "username": user.username or user.title,
                "role": role,
                "selectable": selectable,
                "home": getattr(user, 'home', False),
                "friend": getattr(user, 'friend', False),
                "is_owner": False,
            })
        
        return jsonify({
            "success": True, 
            "owner": owner,
            "users": users,
            "server_name": server_name
        })
        
    except Exception as exc:
        logger.error("Failed to get Plex users: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/plex/history", methods=["GET"])
@login_required
def api_get_user_history():
    """API endpoint to get viewing history for a specific user."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"success": False, "error": "Authorization required"})
    
    server_name = request.args.get('server')
    user_id = request.args.get('user')
    
    if not server_name or not user_id:
        return jsonify({"success": False, "error": "Server name and user ID required"})
    
    # Get account from session - try to reuse existing account object
    account_id = session.get('plex_account_id')
    email = session.get('plex_email')
    password = session.get('plex_password')
    code = session.get('plex_2fa_code')
    
    if not email or not password:
        return jsonify({"success": False, "error": "Authentication session expired"})
    
    try:
        # Try to reuse the global plex_account if it exists and matches
        global plex_account
        if plex_account and hasattr(plex_account, 'id') and plex_account.id == account_id:
            account = plex_account
            logger.info("Reusing existing Plex account session")
        else:
            # Only re-authenticate if we don't have a valid session
            # For 2FA users, avoid re-authentication with same code
            if code:
                # Don't re-authenticate with 2FA code as it's single-use
                # Try without code first, this might work if session is still valid
                try:
                    account = MyPlexAccount(email, password)
                    logger.info("Successfully authenticated with Plex (2FA session still valid)")
                except Exception:
                    # If that fails, we need user to re-authenticate
                    logger.error("2FA session expired, user needs to re-authenticate")
                    return jsonify({"success": False, "error": "2FA session expired, please re-authenticate"})
            else:
                account = MyPlexAccount(email, password)
                logger.info("Successfully authenticated with Plex")
            
            # Update global account reference
            plex_account = account
        
        user_id_int = int(user_id)
        
        # Get viewing history based on user type
        if user_id_int == account.id:
            # Owner history
            movies, episodes = get_owner_plex_history(account)
        else:
            # Managed user history
            movies, episodes = get_managed_user_plex_history(account, user_id_int, server_name)
        
        # Prepare history data
        history_items = []
        
        # Add movies to history
        for movie_data in list(movies.values())[:50]:  # Limit to 50 recent items
            history_items.append({
                "title": movie_data.get("title", "Unknown"),
                "year": movie_data.get("year"),
                "type": "movie",
                "watched_at": movie_data.get("watched_at"),
                "guid": movie_data.get("guid")
            })
        
        # Add episodes to history
        for episode_data in list(episodes.values())[:50]:  # Limit to 50 recent items
            history_items.append({
                "title": episode_data.get("title", "Unknown"),
                "show_title": episode_data.get("show_title"),
                "season": episode_data.get("season"),
                "episode": episode_data.get("episode"),
                "type": "episode",
                "watched_at": episode_data.get("watched_at"),
                "guid": episode_data.get("guid")
            })
        
        # Sort by watched date (most recent first)
        history_items.sort(key=lambda x: x.get("watched_at") or "", reverse=True)
        
        stats = {
            "movies": len(movies),
            "episodes": len(episodes),
            "total": len(movies) + len(episodes)
        }
        
        return jsonify({
            "success": True,
            "stats": stats,
            "history": history_items[:100],  # Return up to 100 items
            "user_id": user_id_int,
            "server_name": server_name
        })
        
    except Exception as exc:
        logger.error("Failed to get user history: %s", exc)
        return jsonify({"success": False, "error": str(exc)})


@app.route("/logout", methods=["POST"])
def logout():
    """Log out from PlexyTrack session only. Does NOT disconnect from Plex/Trakt/Simkl."""
    session.pop("authenticated", None)
    session.pop("auth_user", None)
    return jsonify({"success": True, "message": "Successfully logged out", "redirect": "/login"})


# --------------------------------------------------------------------------- #
# SCHEDULER STARTUP
# --------------------------------------------------------------------------- #
def test_connections() -> bool:
    global plex, _plex_connection_ok
    _plex_connection_ok = False
    # Check session first, then fall back to stored credentials and environment variables
    from flask import has_request_context, session

    plex_token = None
    plex_baseurl = None

    if has_request_context():
        plex_token = session.get('plex_token')
        plex_baseurl = session.get('plex_baseurl')

    if not plex_token or not plex_baseurl:
        stored_token, stored_baseurl = get_session_credentials()
        plex_token = plex_token or stored_token
        plex_baseurl = plex_baseurl or stored_baseurl

    if not plex_token:
        plex_token = os.environ.get("PLEX_TOKEN")
    if not plex_baseurl:
        plex_baseurl = os.environ.get("PLEX_BASEURL")

    plex_baseurl = normalize_baseurl(plex_baseurl)

    trakt_token = os.environ.get("TRAKT_ACCESS_TOKEN")
    trakt_client_id = os.environ.get("TRAKT_CLIENT_ID")
    trakt_enabled = SYNC_PROVIDER == "trakt" and bool(trakt_token and trakt_client_id)
    simkl_token = os.environ.get("SIMKL_ACCESS_TOKEN")
    simkl_client_id = os.environ.get("SIMKL_CLIENT_ID")
    simkl_enabled = SYNC_PROVIDER == "simkl" and bool(simkl_token and simkl_client_id)

    # Require token and base URL for Plex connection
    if not plex_token or not plex_baseurl:
        logger.error("Missing Plex authentication. Provide a token via the web interface or PLEX_TOKEN along with PLEX_BASEURL.")
        return False
    if not trakt_enabled and not simkl_enabled:
        logger.error("Missing environment variables for selected provider.")
        return False

    try:
        plex = get_plex_server()
        if plex is None:
            logger.error("Failed to create Plex server connection")
            return False
        # Test connection by accessing server account info
        plex.account()
        _plex_connection_ok = True
        logger.info("Successfully connected to Plex server.")
    except Exception as exc:
        logger.error("Failed to connect to Plex: %s", exc)
        plex = None
        _plex_connection_ok = False
        return False

    if trakt_enabled:
        headers = {
            "Authorization": f"Bearer {trakt_token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "trakt-api-version": "2",
            "trakt-api-key": trakt_client_id,
        }
        try:
            trakt_request("GET", "/users/settings", headers)
            logger.info("Successfully connected to Trakt.")
        except Exception as exc:
            logger.error("Failed to connect to Trakt: %s", exc)
            return False

    if simkl_enabled:
        headers = {
            "Authorization": f"Bearer {simkl_token}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            "simkl-api-key": simkl_client_id,
        }
        try:
            simkl_request("GET", "/sync/history", headers)
            logger.info("Successfully connected to Simkl.")
        except Exception as exc:
            logger.error("Failed to connect to Simkl: %s", exc)
            return False


    return True


def start_scheduler():
    """Arranca o reinicia el scheduler garantizando **un único** job activo.

    1. Si el scheduler no está corriendo se hace un *start* tras validar
       conexiones.
    2. Antes de añadir el nuevo trabajo se eliminan TODOS los jobs existentes
       para evitar duplicados.
    """
    global scheduler
    stop_event.clear()
    # Recreate scheduler if it was shut down previously
    if scheduler.state == STATE_STOPPED:
        scheduler = BackgroundScheduler()
    # Iniciamos el scheduler si no está corriendo todavía
    if not scheduler.running:
        if not test_connections():
            logger.error("Connection test failed. Scheduler will not start.")
            return
        scheduler.start()
        logger.info("Scheduler started")

    # Eliminamos cualquier job existente para garantizar que sólo haya uno
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
    logger.info("Removed existing scheduled job(s)")

    # Añadimos el nuevo trabajo periódico
    only_watchlist = SYNC_WATCHLISTS and not any(
        [SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS]
    )
    job_func = sync_watchlists_only if only_watchlist else sync
    scheduler.add_job(
        job_func,
        "interval",
        minutes=SYNC_INTERVAL_MINUTES,
        id="sync_job",
        replace_existing=True,
    )
    logger.info(
        "%s job scheduled with interval %d minutes",
        "Watchlist" if only_watchlist else "Sync",
        SYNC_INTERVAL_MINUTES,
    )


def stop_scheduler():
    """Detiene y elimina el job de sincronización dejando el scheduler limpio."""
    global scheduler
    stop_event.set()
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
    if scheduler.running and not scheduler.get_jobs():
        # Si no quedan trabajos activos podemos apagar el scheduler
        scheduler.shutdown(wait=False)
        scheduler = BackgroundScheduler()
    logger.info("Synchronization job(s) stopped")


# --------------------------------------------------------------------------- #
# USER SELECTION FOR SYNC
# --------------------------------------------------------------------------- #

def load_selected_user():
    """Load selected user information from file."""
    try:
        if os.path.exists(SELECTED_USER_FILE):
            with open(SELECTED_USER_FILE, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        pass
    return None

def save_selected_user(user_data):
    """Save selected user information to file."""
    try:
        with open(SELECTED_USER_FILE, 'w') as f:
            json.dump(user_data, f, indent=2)
        return True
    except Exception as exc:
        logger.error("Failed to save selected user: %s", exc)
        return False

def get_selected_user_history(mindate: Optional[str] = None):
    """Get history for the currently selected user."""
    selected_user = load_selected_user()
    if not selected_user:
        logger.warning("No user selected for sync")
        return {}, {}

    account = get_plex_account()
    if not account:
        logger.error("No Plex account available")
        return {}, {}

    if mindate is None:
        mindate = load_last_plex_sync()
        if mindate is None and SAFE_MODE:
            logger.warning(
                "SAFE-MODE active: skipping full Plex history sync"
            )
            return {}, {}

    if selected_user["is_owner"]:
        logger.debug(
            "Getting history for owner since %s", mindate or "beginning"
        )
        return get_owner_plex_history(account, mindate=mindate)
    else:
        logger.debug(
            "Getting history for managed user %s since %s",
            selected_user["username"],
            mindate or "beginning",
        )
        return get_managed_user_plex_history(
            account, selected_user["id"], mindate=mindate
        )

# Cache for users to avoid repeated API calls
_cached_users = None
_cached_users_timestamp = None
CACHE_DURATION = 300  # 5 minutes

def reset_cache():
    """Reset all cached data to ensure fresh data on sync start"""
    global _cached_users, _cached_users_timestamp, plex, plex_account, _plex_connection_ok
    _cached_users = None
    _cached_users_timestamp = None
    
    # Reset Plex connection to force re-authentication with current credentials
    plex = None
    plex_account = None
    _plex_connection_ok = False
    
    # Reset sections cache from utils.py
    from utils import reset_sections_cache
    reset_sections_cache()
    
    # Reset movie and show GUID caches from plex_utils.py
    from plex_utils import reset_movie_guid_cache, reset_show_guid_cache
    reset_movie_guid_cache()
    reset_show_guid_cache()
    
    logger.debug("Cache reset - all cached data cleared (users, sections, movie GUIDs, show GUIDs, and Plex connection)")

def get_cached_users(account):
    """Get cached users list to avoid repeated API calls"""
    global _cached_users, _cached_users_timestamp
    current_time = time.time()
    
    if (_cached_users is None or 
        _cached_users_timestamp is None or 
        current_time - _cached_users_timestamp > CACHE_DURATION):
        _cached_users = account.users()
        _cached_users_timestamp = current_time
        logger.debug("Refreshed user cache with %d users", len(_cached_users))
    
    return _cached_users

def mark_as_watched_for_user(
    item_guid,
    item_type,
    user_data,
    *,
    title=None,
    year=None,
    show_title=None,
    code=None,
):
    """
    Mark an item as watched for the selected user.
    Uses scrobble for managed users, direct marking for owner.
    """
    start_time = time.time()
    try:
        plex_server = get_plex_server()
        account = get_plex_account()
        
        if not plex_server or not account:
            logger.error("Plex connection not available")
            return False
        
        # Find the item in Plex
        search_start = time.time()
        item = find_item_by_guid(plex_server, item_guid)
        search_duration = time.time() - search_start

        if not item:
            logger.debug(
                "Item not found by GUID in Plex: %s (type: %s) - search took %.2fs",
                item_guid,
                item_type,
                search_duration,
            )

            # Fallback search by title/year or show/code
            if item_type == "movie" and title:
                for section in plex_server.library.sections():
                    if section.type != "movie":
                        continue
                    try:
                        results = section.search(title=title)
                        for candidate in results:
                            if year is None or normalize_year(getattr(candidate, "year", None)) == normalize_year(year):
                                item = candidate
                                break
                        if item:
                            break
                    except Exception:
                        continue
            elif item_type == "episode" and show_title and code:
                try:
                    season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
                except ValueError:
                    season_num = episode_num = None
                show_obj = get_show_from_library(plex_server, show_title)
                if show_obj and season_num is not None and episode_num is not None:
                    try:
                        item = show_obj.episode(season=season_num, episode=episode_num)
                    except Exception:
                        item = None

            if not item:
                return False
        
        # Validate item type matches expectation
        actual_type = getattr(item, 'TYPE', 'unknown')
        if item_type == "movie" and actual_type != "movie":
            logger.warning(
                "Type mismatch: expected movie but found %s for %s. Skipping",
                actual_type,
                item.title,
            )
            return False
        elif item_type == "episode" and actual_type != "episode":
            logger.warning(
                "Type mismatch: expected episode but found %s for %s. Skipping",
                actual_type,
                item.title,
            )
            return False
            
        # Check if already watched
        if hasattr(item, 'isWatched') and item.isWatched:
            logger.debug("Item %s is already marked as watched, skipping", item.title)
            return True
            
        if user_data["is_owner"]:
            # For owner, mark directly
            mark_start = time.time()
            try:
                # Double-check that the item can be marked as watched
                if hasattr(item, 'markWatched'):
                    item.markWatched()
                    mark_duration = time.time() - mark_start
                    total_duration = time.time() - start_time
                    logger.debug("Marked %s as watched for owner: %s (search: %.2fs, mark: %.2fs, total: %.2fs)", 
                                item_type, item.title, search_duration, mark_duration, total_duration)
                    
                    # Verify the item is now marked as watched
                    try:
                        # Refresh item data to get latest status
                        item.reload()
                        if hasattr(item, 'isWatched') and item.isWatched:
                            logger.debug("Verified %s is now marked as watched: %s", item_type, item.title)
                        else:
                            logger.warning("Item may not have been properly marked as watched: %s", item.title)
                    except Exception as verify_exc:
                        logger.debug("Could not verify watched status: %s", verify_exc)
                    
                    return True
                else:
                    logger.error("Item %s does not support markWatched method", item.title)
                    return False
            except Exception as mark_exc:
                logger.error("Failed to mark %s as watched for owner: %s - %s", item_type, item.title, mark_exc)
                return False
        else:
            # For managed users, use scrobble method
            try:
                # Get the managed user object using cached users
                user_lookup_start = time.time()
                managed_user = None
                cached_users = get_cached_users(account)
                for user in cached_users:
                    if str(user.id) == str(user_data["id"]):
                        managed_user = user
                        break
                user_lookup_duration = time.time() - user_lookup_start
                
                if managed_user:
                    # Switch to the managed user's account for marking as watched
                    try:
                        user_account = account.switchHomeUser(managed_user.title)
                        if user_account:
                            # Connect to server with managed user account strictly via configured base URL
                            try:
                                from plexapi.server import PlexServer as _PlexServer
                                managed_baseurl = normalize_baseurl(os.environ.get("PLEX_BASEURL"))
                                managed_token = getattr(user_account, 'authToken', None)
                                if not managed_baseurl or not managed_token:
                                    raise RuntimeError("Missing PLEX_BASEURL or managed user token")
                                user_plex = _PlexServer(managed_baseurl, managed_token)
                            except Exception as connect_exc:
                                logger.error("Failed to connect to Plex as managed user strictly via PLEX_BASEURL: %s", connect_exc)
                                return False
                            
                            # Find the item from the managed user's perspective
                            user_item = find_item_by_guid(user_plex, item_guid)
                            if not user_item:
                                if item_type == "movie" and title:
                                    for section in user_plex.library.sections():
                                        if section.type != "movie":
                                            continue
                                        try:
                                            results = section.search(title=title)
                                            for candidate in results:
                                                if year is None or normalize_year(getattr(candidate, "year", None)) == normalize_year(year):
                                                    user_item = candidate
                                                    break
                                            if user_item:
                                                break
                                        except Exception:
                                            continue
                                elif item_type == "episode" and show_title and code:
                                    try:
                                        season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
                                    except ValueError:
                                        season_num = episode_num = None
                                    show_obj = get_show_from_library(user_plex, show_title)
                                    if show_obj and season_num is not None and episode_num is not None:
                                        try:
                                            user_item = show_obj.episode(season=season_num, episode=episode_num)
                                        except Exception:
                                            user_item = None

                            if user_item:
                                user_item.markWatched()
                                logger.info(
                                    "Marked %s as watched for managed user %s: %s",
                                    item_type,
                                    user_data["username"],
                                    item.title,
                                )
                                return True
                            else:
                                # Alternative: mark as watched from main server for this user
                                logger.warning(
                                    "Item not accessible from managed user perspective, marking via main server"
                                )
                                item.markWatched()
                                logger.info(
                                    "Marked %s as watched for managed user %s via main server: %s",
                                    item_type,
                                    user_data["username"],
                                    item.title,
                                )
                                return True
                        else:
                            logger.error("Could not switch to managed user: %s", user_data["username"])
                            return False
                    except Exception as switch_exc:
                        logger.error("Failed to switch to managed user %s: %s", user_data["username"], switch_exc)
                        # Fallback: try to mark as watched from main server
                        try:
                            item.markWatched()
                            logger.info("Fallback mark as watched successful for %s: %s", user_data["username"], item.title)
                            return True
                        except Exception as mark_exc:
                            logger.error("Fallback mark as watched also failed: %s", mark_exc)
                            return False
                else:
                    logger.error("Managed user not found: %s", user_data["username"])
                    return False
            except Exception as exc:
                logger.error("Failed to mark as watched for managed user %s: %s", 
                           user_data["username"], exc)
                # Fallback: try marking as watched from main server
                try:
                    item.markWatched()
                    logger.info("Fallback mark as watched successful for %s: %s", user_data["username"], item.title)
                    return True
                except Exception as mark_exc:
                    logger.error("Fallback mark as watched also failed: %s", mark_exc)
                    return False
                
    except Exception as exc:
        logger.error("Failed to mark as watched: %s", exc)
        return False



@app.route("/api/select_user", methods=["POST"])
@login_required
def select_user():
    """API endpoint to select a user for sync operations."""
    try:
        data = request.json
        user_id = data.get("user_id")
        username = data.get("username")
        role = data.get("role")
        is_owner = data.get("is_owner", False)
        
        if not user_id or not username:
            return jsonify({"success": False, "error": "Missing user data"})
        
        user_data = {
            "id": user_id,
            "username": username,
            "role": role,
            "is_owner": is_owner,
            "selected_at": datetime.now().isoformat()
        }
        
        if save_selected_user(user_data):
            logger.info("Selected user for sync: %s (%s)", username, role)
            message = f"Selected {username} for sync"
            return jsonify({"success": True, "message": message})
        else:
            return jsonify({"success": False, "error": "Failed to save user selection"})
            
    except Exception as exc:
        logger.error("Failed to select user: %s", exc)
        return jsonify({"success": False, "error": str(exc)})

@app.route("/api/get_selected_user")
@login_required
def get_selected_user_api():
    """API endpoint to get currently selected user."""
    selected_user = load_selected_user()
    if selected_user:
        return jsonify({"success": True, "user": selected_user})
    else:
        return jsonify({"success": False, "user": None})

# --------------------------------------------------------------------------- #
# SESSION CREDENTIALS MANAGEMENT
# --------------------------------------------------------------------------- #
def save_session_credentials(token=None, baseurl=None):
    """Save Plex token and base URL for scheduler access."""
    global session_plex_credentials
    session_plex_credentials['token'] = token
    session_plex_credentials['baseurl'] = normalize_baseurl(baseurl)
    logger.info("Session credentials saved for scheduler access")

def get_session_credentials():
    """Get Plex token and base URL from session storage."""
    global session_plex_credentials
    return (
        session_plex_credentials.get('token'),
        session_plex_credentials.get('baseurl')
    )

def clear_session_credentials():
    """Clear stored session credentials."""
    global session_plex_credentials
    session_plex_credentials = {'token': None, 'baseurl': None}
    logger.info("Session credentials cleared")


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    logger.info("Starting PlexyTrackt application")
    ensure_directory(CONFIG_DIR)
    ensure_directory(STATE_DIR)
    verify_volume(CONFIG_DIR, "config")
    migrate_legacy_state()
    verify_volume(STATE_DIR, "state")
    state_data = load_state()
    ensure_default_credentials()
    load_trakt_tokens()
    load_simkl_tokens()
    load_plex_token()
    load_provider()
    load_settings()
    if state_data.get("lastSync") is None and not SYNC_WATCHED:
        SAFE_MODE = True
        logger.warning(
            "No last sync timestamp and history sync disabled; entering SAFE-MODE"
        )
    # Removed automatic scheduler start - only manual start from sync tab
    # start_scheduler()
    # Disable Flask's auto-reloader to avoid duplicate logs
    app.run(host="0.0.0.0", port=5030, use_reloader=False)
