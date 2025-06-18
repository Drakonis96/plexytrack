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
from datetime import datetime, timezone
from numbers import Number
from typing import Dict, List, Optional, Set, Tuple, Union
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
from flask import send_file, session
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_STOPPED
from plexapi.server import PlexServer
from plexapi.myplex import MyPlexAccount
from plexapi.exceptions import BadRequest, NotFound
from getpass import getpass

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
from plex_utils import get_plex_history, update_plex, get_user_plex_history, get_user_watch_counts, get_owner_watch_counts, get_managed_user_watch_counts, get_owner_plex_history, get_managed_user_plex_history
from trakt_utils import (
    load_trakt_tokens,
    save_trakt_tokens,
    exchange_code_for_tokens,
    refresh_trakt_token,
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
    restore_backup,
    load_trakt_last_sync_date,
    save_trakt_last_sync_date,
    get_trakt_last_activity,
)
from simkl_utils import (
    load_simkl_tokens,
    save_simkl_token,
    exchange_code_for_simkl_tokens,
    simkl_request,
    get_simkl_history,
    update_simkl,
    load_last_sync_date,
    save_last_sync_date,
    get_last_activity,
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
APP_VERSION = "v0.2.7"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"

# --------------------------------------------------------------------------- #
# FLASK + APSCHEDULER
# --------------------------------------------------------------------------- #
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-in-production')

SYNC_INTERVAL_MINUTES = 60  # default frequency
SYNC_COLLECTION = False
SYNC_RATINGS = True
SYNC_WATCHED = True  # ahora sí se respeta este flag
SYNC_LIKED_LISTS = False
SYNC_WATCHLISTS = False
LIVE_SYNC = False
SYNC_PROVIDER = "none"  # trakt | simkl | none
PROVIDER_FILE = "provider.json"
scheduler = BackgroundScheduler()
plex = None  # will hold PlexServer instance
plex_account = None  # will hold MyPlexAccount instance

# Global storage for session-based Plex credentials (for scheduler access)
session_plex_credentials = {
    'email': None,
    'password': None,
    'code': None,
    'token': None,  # Store the authentication token
    'baseurl': None  # Store the server baseurl if available
}

# --------------------------------------------------------------------------- #
# TRAKT / SIMKL OAUTH CONSTANTS
# --------------------------------------------------------------------------- #
TRAKT_REDIRECT_URI = os.environ.get("TRAKT_REDIRECT_URI")
TOKEN_FILE = "trakt_tokens.json"

SIMKL_REDIRECT_URI = os.environ.get("SIMKL_REDIRECT_URI")
SIMKL_TOKEN_FILE = "simkl_tokens.json"


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
# CUSTOM EXCEPTIONS
# --------------------------------------------------------------------------- #
class TraktAccountLimitError(Exception):
    """Raised when Trakt returns HTTP 420 (account limit exceeded)."""

    pass


def get_trakt_redirect_uri() -> str:
    """Return the Trakt redirect URI derived from the current request."""
    global TRAKT_REDIRECT_URI
    if TRAKT_REDIRECT_URI:
        return TRAKT_REDIRECT_URI
    if has_request_context():
        TRAKT_REDIRECT_URI = request.url_root.rstrip("/") + "/oauth/trakt"
        return TRAKT_REDIRECT_URI
    return "http://localhost:5030/oauth/trakt"


def get_simkl_redirect_uri() -> str:
    """Return the Simkl redirect URI derived from the current request."""
    global SIMKL_REDIRECT_URI
    if SIMKL_REDIRECT_URI:
        return SIMKL_REDIRECT_URI
    if has_request_context():
        SIMKL_REDIRECT_URI = request.url_root.rstrip("/") + "/oauth/simkl"
        return SIMKL_REDIRECT_URI
    return "http://localhost:5030/oauth/simkl"


def get_plex_server_legacy():
    """
    Legacy fallback method using token authentication.
    Used when credentials are not provided.
    """
    baseurl = os.environ.get("PLEX_BASEURL")
    token = os.environ.get("PLEX_TOKEN")
    if not baseurl or not token:
        return None
    try:
        from plexapi.server import PlexServer
        return PlexServer(baseurl, token)
    except Exception as exc:
        logger.error("Failed to connect to Plex using legacy token method: %s", exc)
        return None


def get_plex_server():
    """Return a connected :class:`PlexServer` instance or ``None``."""
    global plex, plex_account
    if plex is None:
        # Check session first, then fall back to environment variables
        from flask import has_request_context, session
        email = None
        password = None
        token = None
        baseurl = None
        
        if has_request_context():
            email = session.get('plex_email')
            password = session.get('plex_password')
            token = session.get('plex_token')
        
        # If not in request context or session empty, check global session credentials
        if not token and (not email or not password):
            email, password, _, token, baseurl = get_session_credentials()
        
        # Fall back to environment variables if session data not available
        if not token:
            if not email or not password:
                email = os.environ.get("PLEX_EMAIL")
                password = os.environ.get("PLEX_PASSWORD")
            if not baseurl:
                baseurl = os.environ.get("PLEX_BASEURL")
                env_token = os.environ.get("PLEX_TOKEN")
                if env_token and baseurl:
                    token = env_token

        # Try token-based authentication first (avoids 2FA re-authentication)
        if token:
            try:
                if baseurl:
                    # Direct server connection with token
                    from plexapi.server import PlexServer
                    plex = PlexServer(baseurl, token)
                    logger.info("Successfully connected to Plex using token (direct)")
                else:
                    # Use token to create account, then get server
                    plex_account = MyPlexAccount(token=token)
                    logger.info("Successfully authenticated with Plex using token")
                    
                    # Get the server
                    server_name = os.environ.get("PLEX_SERVER_NAME")
                    if server_name:
                        resource = plex_account.resource(server_name)
                        plex = resource.connect()
                        logger.info("Connected to Plex server: %s", server_name)
                    else:
                        resources = plex_account.resources()
                        plex_resources = [r for r in resources if r.product == 'Plex Media Server']
                        if not plex_resources:
                            logger.error("No Plex Media Server found in account")
                            return None
                        plex = plex_resources[0].connect()
                        logger.info("Connected to Plex server: %s", plex_resources[0].name)
                        
                return plex
                        
            except Exception as exc:
                logger.warning("Token-based authentication failed: %s", exc)
                # Continue to email/password authentication
                
        # Fallback to email/password authentication
        if email and password:
            try:
                # Intentar login básico primero
                try:
                    plex_account = MyPlexAccount(email, password)
                    logger.info("Successfully authenticated with Plex (no 2FA required)")
                except Exception as first_exc:
                    # Si falla, verificar si necesita 2FA
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
                        logger.info("2FA required for Plex authentication")
                        from flask import redirect, url_for, has_request_context
                        if has_request_context():
                            # Just return None and let the caller handle it
                            return None
                        otp = os.environ.get("PLEX_2FA_CODE")
                        if not otp:
                            logger.error("2FA required but PLEX_2FA_CODE not provided")
                            return None
                        plex_account = MyPlexAccount(email, password, code=otp)
                        logger.info("Successfully authenticated with Plex using 2FA")
                    else:
                        # Si no es un error de 2FA, re-lanzar la excepción
                        raise first_exc
                
                logger.info("2FA active: %s", plex_account.twoFactorEnabled)
                
                # Obtener el servidor de Plex
                server_name = os.environ.get("PLEX_SERVER_NAME")
                if server_name:
                    # Usar servidor específico
                    resource = plex_account.resource(server_name)
                    plex = resource.connect()
                    logger.info("Connected to Plex server: %s", server_name)
                else:
                    # Usar el primer servidor disponible
                    resources = plex_account.resources()
                    plex_resources = [r for r in resources if r.product == 'Plex Media Server']
                    if not plex_resources:
                        logger.error("No Plex Media Server found in account")
                        return None
                    plex = plex_resources[0].connect()
                    logger.info("Connected to Plex server: %s", plex_resources[0].name)
                    
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to connect to Plex using credentials: %s", exc)
                from flask import redirect, url_for, has_request_context
                error_str = str(exc).lower()
                
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
                
                if has_request_context() and requires_2fa:
                    # Just return None and let the page handle 2FA
                    return None
                plex = None
                plex_account = None
        else:
            # Fallback: método legacy con token
            logger.warning("No Plex authentication credentials available")
            plex = get_plex_server_legacy()
            plex_account = None  # No account available with token method
            
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


def _parse_guid_value(raw: str) -> Optional[str]:
    """Convert a raw Plex GUID string to a known imdb/tmdb/tvdb/anidb prefix."""
    if raw.startswith("imdb://"):
        return raw.split("?", 1)[0]
    if raw.startswith("tmdb://"):
        return raw.split("?", 1)[0]
    if raw.startswith("tvdb://"):
        return raw.split("?", 1)[0]
    if raw.startswith("anidb://"):
        return raw.split("?", 1)[0]
    if "themoviedb://" in raw:
        val = raw.split("themoviedb://", 1)[1].split("?", 1)[0]
        return f"tmdb://{val.split('/')[0]}"
    if "thetvdb://" in raw:
        val = raw.split("thetvdb://", 1)[1].split("?", 1)[0]
        return f"tvdb://{val.split('/')[0]}"
    if "imdb://" in raw:
        val = raw.split("imdb://", 1)[1].split("?", 1)[0]
        return f"imdb://{val.split('/')[0]}"
    return None


def best_guid(item) -> Optional[str]:
    """Return a preferred GUID (imdb → tmdb → tvdb) for a Plex item."""
    try:
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and val.startswith("imdb://"):
                return val
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and (val.startswith("tmdb://") or val.startswith("tvdb://")):
                return val
        if getattr(item, "guid", None):
            return _parse_guid_value(item.guid)
    except Exception as exc:
        logger.debug("Failed retrieving GUIDs: %s", exc)
    return None


def imdb_guid(item) -> Optional[str]:
    """Return an IMDb, TMDb, TVDb or AniDB GUID for a Plex item."""
    try:
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and val.startswith("imdb://"):
                return val
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and val.startswith("tmdb://"):
                return val
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and val.startswith("tvdb://"):
                return val
        for g in getattr(item, "guids", []) or []:
            val = _parse_guid_value(g.id)
            if val and val.startswith("anidb://"):
                return val
        if getattr(item, "guid", None):
            val = _parse_guid_value(item.guid)
            if val and val.startswith("imdb://"):
                return val
            if val and val.startswith("tmdb://"):
                return val
            if val and val.startswith("tvdb://"):
                return val
            if val and val.startswith("anidb://"):
                return val
    except Exception as exc:
        logger.debug("Failed retrieving IMDb GUID: %s", exc)
    return None


def get_show_from_library(plex, title):
    """Return a show object from any library section."""
    for sec in plex.library.sections():
        if sec.type == "show":
            try:
                # Intento 1: coincidencia exacta (rápido)
                return sec.get(title)
            except NotFound:
                # Intento 2: búsqueda flexible
                try:
                    results = sec.search(title=title)
                    if results:
                        return results[0]
                except Exception:
                    pass
                continue
    return None


def find_item_by_guid(plex, guid):
    """Return a movie or show from Plex matching the given GUID."""
    for sec in plex.library.sections():
        if sec.type in ("movie", "show"):
            try:
                return sec.getGuid(guid)
            except Exception:
                continue
    return None


def ensure_collection(plex, section, name, first_item=None):
    """Return a Plex collection with ``name`` creating it if needed."""
    try:
        return section.collection(name)
    except Exception:
        if first_item is None:
            raise
        return plex.createCollection(name, section, items=[first_item])


def movie_key(
    title: str, year: Optional[int], guid: Optional[str]
) -> Union[str, Tuple[str, Optional[int]]]:
    """Return a unique key for comparing movies."""
    if guid:
        return guid
    return (title, year)


def guid_to_ids(guid: Union[str, Tuple[str, str]]) -> Dict[str, Union[str, int]]:
    """Convert a Plex GUID to a Trakt ids mapping."""
    # Handle tuple format (used for episodes: (guid, episode_info))
    if isinstance(guid, tuple):
        guid = guid[0] if guid else ""
    
    # Handle string format
    if not isinstance(guid, str):
        return {}
        
    if guid.startswith("imdb://"):
        return {"imdb": guid.split("imdb://", 1)[1]}
    if guid.startswith("tmdb://"):
        return {"tmdb": int(guid.split("tmdb://", 1)[1])}
    if guid.startswith("tvdb://"):
        return {"tvdb": int(guid.split("tvdb://", 1)[1])}
    if guid.startswith("anidb://"):
        return {"anidb": int(guid.split("anidb://", 1)[1])}
    return {}



def trakt_movie_key(m: dict) -> Union[str, Tuple[str, Optional[int]]]:
    """Return a unique key for a Trakt movie object using IMDb, TMDb, TVDb o AniDB."""
    ids = m.get("ids", {})
    if ids.get("imdb"):
        return f"imdb://{ids['imdb']}"
    if ids.get("tmdb"):
        return f"tmdb://{ids['tmdb']}"
    if ids.get("tvdb"):
        return f"tvdb://{ids['tvdb']}"
    if ids.get("anidb"):
        return f"anidb://{ids['anidb']}"
    return m["title"].lower()


def episode_key(
    show: str, code: str, guid: Optional[str]
) -> Union[str, Tuple[str, str]]:
    if guid and (guid.startswith(("imdb://", "tmdb://", "tvdb://", "anidb://"))):
        return guid
    return (show.lower(), code)


def trakt_episode_key(show: dict, e: dict) -> Union[str, Tuple[str, str]]:
    ids = e.get("ids", {})
    if ids.get("imdb"):
        return f"imdb://{ids['imdb']}"
    if ids.get("tmdb"):
        return f"tmdb://{ids['tmdb']}"
    if ids.get("tvdb"):
        return f"tvdb://{ids['tvdb']}"
    if ids.get("anidb"):
        return f"anidb://{ids['anidb']}"
    return (
        show["title"].lower(),
        f"S{e['season']:02d}E{e['number']:02d}",
    )


def simkl_episode_key(show: dict, e: dict) -> Optional[Union[str, Tuple[str, str]]]:
    """Return best key for a Simkl episode object.

    Siempre que exista un identificador único a nivel de episodio (IMDb/TMDb/TVDb/AniDB)
    se utiliza dicho GUID como clave. Cuando no hay identificadores a nivel de
    episodio —algo bastante habitual en Simkl— se genera una clave compuesta
    (GUID_serie, "SxxEyy") para evitar que distintos episodios de una misma
    serie colisionen entre sí.
    """
    ids = e.get("ids", {}) or {}
    if ids.get("imdb"):
        return f"imdb://{ids['imdb']}"
    if ids.get("tmdb"):
        return f"tmdb://{ids['tmdb']}"
    if ids.get("tvdb"):
        return f"tvdb://{ids['tvdb']}"
    if ids.get("anidb"):
        return f"anidb://{ids['anidb']}"

    # -------------------------- Fallback -------------------------- #
    # Sin IDs de episodio: combinamos GUID (de la serie) + código epi.
    show_ids = show.get("ids", {}) or {}
    base_guid: Optional[str] = None
    if show_ids.get("imdb"):
        base_guid = f"imdb://{show_ids['imdb']}"
    elif show_ids.get("tmdb"):
        base_guid = f"tmdb://{show_ids['tmdb']}"
    elif show_ids.get("tvdb"):
        base_guid = f"tvdb://{show_ids['tvdb']}"
    elif show_ids.get("anidb"):
        base_guid = f"anidb://{show_ids['anidb']}"

    # Componer código SxxEyy
    season_num = e.get("season", 0)
    episode_num = e.get("number", 0)
    code = f"S{season_num:02d}E{episode_num:02d}"

    # Si no hay GUID de serie, usamos (titulo, code) como último recurso.
    if base_guid:
        return (base_guid, code)
    return (show.get("title", "").lower(), code)



# --------------------------------------------------------------------------- #
# TRAKT TOKENS
# --------------------------------------------------------------------------- #
def load_trakt_tokens() -> None:
    if os.environ.get("TRAKT_ACCESS_TOKEN") and os.environ.get("TRAKT_REFRESH_TOKEN"):
        return
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            os.environ["TRAKT_ACCESS_TOKEN"] = data.get("access_token", "")
            os.environ["TRAKT_REFRESH_TOKEN"] = data.get("refresh_token", "")
            logger.info("Loaded Trakt tokens from %s", TOKEN_FILE)
        except Exception as exc:
            logger.error("Failed to load Trakt tokens: %s", exc)


def save_trakt_tokens(access_token: str, refresh_token: Optional[str]) -> None:
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump(
                {"access_token": access_token, "refresh_token": refresh_token},
                f,
                indent=2,
            )
        logger.info("Saved Trakt tokens to %s", TOKEN_FILE)
    except Exception as exc:
        logger.error("Failed to save Trakt tokens: %s", exc)


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
    save_trakt_tokens(data["access_token"], data.get("refresh_token"))
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
    save_trakt_tokens(data["access_token"], os.environ["TRAKT_REFRESH_TOKEN"])
    logger.info("Trakt access token refreshed")
    return data["access_token"]


def load_simkl_tokens() -> None:
    if os.environ.get("SIMKL_ACCESS_TOKEN"):
        return
    if os.path.exists(SIMKL_TOKEN_FILE):
        try:
            with open(SIMKL_TOKEN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            os.environ["SIMKL_ACCESS_TOKEN"] = data.get("access_token", "")
            logger.info("Loaded Simkl token from %s", SIMKL_TOKEN_FILE)
        except Exception as exc:
            logger.error("Failed to load Simkl token: %s", exc)


def save_simkl_token(access_token: str) -> None:
    try:
        with open(SIMKL_TOKEN_FILE, "w", encoding="utf-8") as f:
            json.dump({"access_token": access_token}, f, indent=2)
        logger.info("Saved Simkl token to %s", SIMKL_TOKEN_FILE)
    except Exception as exc:
        logger.error("Failed to save Simkl token: %s", exc)


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
    save_simkl_token(data["access_token"])
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


def simkl_request(
    method: str,
    endpoint: str,
    headers: dict,
    *,
    retries: int = 2,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """Realiza una petición HTTP a la API de Simkl con reintentos y timeout adaptable.

    • `retries`  – número de reintentos ante ReadTimeout (por defecto 2 → 3 intentos totales).
    • `timeout`  – timeout inicial en segundos (por defecto 30 s). Cada reintento duplica el timeout.
    """

    url = f"https://api.simkl.com{endpoint}"

    headers.setdefault("User-Agent", USER_AGENT)

    # Extraer un timeout personalizado si viene en **kwargs** para mantener compatibilidad.
    if "timeout" in kwargs:
        timeout = kwargs.pop("timeout")  # se usará como valor inicial

    attempt = 0
    while True:
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.exceptions.ReadTimeout as exc:
            if attempt >= retries:
                logger.error("Simkl ReadTimeout tras %d intentos (%d s).", attempt + 1, timeout)
                raise
            attempt += 1
            timeout *= 2  # back-off exponencial
            logger.warning(
                "Simkl request %s %s agotó el tiempo (%s). Reintentando (%d/%d) con timeout=%ds…",
                method.upper(), endpoint, exc, attempt, retries, timeout,
            )
        except requests.exceptions.RequestException:
            # Para otros errores de red no merece volver a intentar; relanzamos.
            raise


def simkl_search_ids(
    headers: dict,
    title: str,
    *,
    is_movie: bool = True,
    year: Optional[int] = None,
) -> Dict[str, Union[str, int]]:
    """Buscar en Simkl por *title* y devolver un mapping de IDs.

    Si no se encuentra un resultado claro se devuelve un dict vacío.
    """
    endpoint = "/search/movies" if is_movie else "/search/shows"
    params = {"q": title, "limit": 1}
    # Algunos endpoints aceptan el parámetro `year` únicamente para películas.
    if year and is_movie:
        params["year"] = year
    try:
        resp = simkl_request("GET", endpoint, headers, params=params)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Simkl search failed for '%s': %s", title, exc)
        return {}

    if not isinstance(data, list) or not data:
        return {}

    ids = data[0].get("ids", {}) or {}
    # Normalizar integer IDs
    for k, v in list(ids.items()):
        try:
            ids[k] = int(v) if str(v).isdigit() else v
        except Exception:
            pass
    return ids


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


def simkl_movie_key(m: dict) -> Optional[str]:
    """Return best GUID for a Simkl movie object."""
    ids = m.get("ids", {})
    if ids.get("imdb"):
        return f"imdb://{ids['imdb']}"
    if ids.get("tmdb"):
        return f"tmdb://{ids['tmdb']}"
    if ids.get("tvdb"):
        return f"tvdb://{ids['tvdb']}"
    if ids.get("anidb"):
        return f"anidb://{ids['anidb']}"
    return None


def get_simkl_history(
    headers: dict,
    *,
    date_from: Optional[str] = None,
) -> Tuple[
    Dict[str, Tuple[str, Optional[int], Optional[str]]],
    Dict[str, Tuple[str, str, Optional[str]]],
]:
    """Return Simkl movie and episode history keyed on best GUID.
    
    Returns:
        Tuple containing:
        - Movies: Dict[guid, (title, year, watched_at)]
        - Episodes: Dict[guid, (show_title, episode_code, watched_at)]
    """
    movies: Dict[str, Tuple[str, Optional[int], Optional[str]]] = {}
    episodes: Dict[str, Tuple[str, str, Optional[str]]] = {}
    
    # First, get movies from sync/history (watched history)
    params = {"type": "movies"}
    if date_from:
        params["date_from"] = date_from
    logger.info("Fetching Simkl watch history…")
    resp = simkl_request(
        "GET",
        "/sync/history",
        headers,
        params=params,
    )
    data = resp.json()
    if isinstance(data, list):
        for item in data:
            m = item.get("movie", {})
            guid = simkl_movie_key(m)
            if not guid:
                continue
            if guid not in movies:
                movies[guid] = (
                    m.get("title"),
                    normalize_year(m.get("year")),
                    item.get("watched_at"),
                )
    
    # Get episodes from sync/history
    params = {"type": "episodes"}
    if date_from:
        params["date_from"] = date_from
    logger.info("Fetching Simkl episode history…")
    resp = simkl_request(
        "GET",
        "/sync/history",
        headers,
        params=params,
    )
    data = resp.json()
    if isinstance(data, list):
        for item in data:
            e = item.get("episode", {})
            show = item.get("show", {})
            guid = simkl_episode_key(show, e)
            if not guid:
                continue
            if guid not in episodes:
                episodes[guid] = (
                    show.get("title"),
                    f"S{e.get('season', 0):02d}E{e.get('number', 0):02d}",
                    item.get("watched_at"),
                )
    
    # Then, get movies from sync/all-items to include completed movies
    logger.info("Fetching Simkl all-items (full)…")
    resp = simkl_request(
        "GET",
        "/sync/all-items",
        headers,
        params={"extended": "full", "episode_watched_at": "yes"},
    )
    data = resp.json()
    if data and isinstance(data, dict):
        completed_movies = data.get("movies", [])
        for movie_item in completed_movies:
            m = movie_item.get("movie", {})
            guid = simkl_movie_key(m)
            if not guid:
                continue
            if guid not in movies:
                # For completed movies, use last_watched_at if available
                watched_at = movie_item.get("last_watched_at")
                movies[guid] = (
                    m.get("title"),
                    normalize_year(m.get("year")),
                    watched_at,
                )
        
        # Get completed episodes from shows in all-items
        completed_shows = data.get("shows", [])
        for show_item in completed_shows:
            show = show_item.get("show", {})
            seasons = show_item.get("seasons", [])
            for season in seasons:
                season_num = season.get("number", 0)
                season_episodes = season.get("episodes", [])
                for episode in season_episodes:
                    # Determinar si el episodio está visto:
                    # 1. Si viene `watched_at`, asumimos visto.
                    # 2. Si no, usamos la métrica `plays` (reproducido ≥1).
                    # 3. Si tampoco hay `plays`, comprobamos `watched` (bool).
                    if not (
                        episode.get("watched_at")
                        or episode.get("plays", 0) > 0
                        or episode.get("watched")
                    ):
                        # No hay indicios de reproducción → saltar
                        continue

                    episode_num = episode.get("number", 0)

                    # Crear un objeto "episode" compatible con simkl_episode_key
                    e = {
                        "season": season_num,
                        "number": episode_num,
                        "ids": episode.get("ids", {}),
                    }

                    guid = simkl_episode_key(show, e)
                    if not guid:
                        continue

                    if guid not in episodes:
                        episodes[guid] = (
                            show.get("title"),
                            f"S{season_num:02d}E{episode_num:02d}",
                            episode.get("watched_at"),
                        )
    
    return movies, episodes


def update_simkl(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Add new items to Simkl history con búsqueda de IDs de respaldo."""
    payload = {}
    if movies:
        payload["movies"] = []
        for title, year, guid, watched_at in movies:
            item = {"title": title, "year": normalize_year(year)}
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, title, is_movie=True, year=year)
                if ids:
                    logger.debug("IDs found in Simkl for movie '%s': %s", title, ids)
            if ids:
                item["ids"] = ids
            if watched_at:
                item["watched_at"] = watched_at
            payload["movies"].append(item)

    if episodes:
        shows: Dict[str, dict] = {}
        for show_title, code, guid, watched_at in episodes:
            # Intentar obtener IDs de la serie
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, show_title, is_movie=False)
                if ids:
                    logger.debug("IDs found in Simkl for show '%s': %s", show_title, ids)
            if not ids:
                logger.warning(
                    "Skipping episode '%s - %s' - no IDs found", show_title, code
                )
                continue

            key = tuple(sorted(ids.items()))  # clave única para la serie
            if key not in shows:
                shows[key] = {
                    "title": show_title,
                    "ids": ids,
                    "seasons": [],
                }

            try:
                season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
            except ValueError:
                logger.warning("Invalid episode code format: %s", code)
                continue

            season_found = False
            for s in shows[key]["seasons"]:
                if s["number"] == season_num:
                    s["episodes"].append({"number": episode_num, "watched_at": watched_at})
                    season_found = True
                    break

            if not season_found:
                shows[key]["seasons"].append(
                    {
                        "number": season_num,
                        "episodes": [{"number": episode_num, "watched_at": watched_at}],
                    }
                )
        if shows:
            payload["shows"] = list(shows.values())

    if not payload:
        logger.info("Nothing new to sync with Simkl")
        return

    logger.info(
        "Adding %d movies and %d shows to Simkl history",
        len(payload.get("movies", [])),
        len(payload.get("shows", [])),
    )
    try:
        response = simkl_request(
            "post", "/sync/history", headers, json=payload
        )
        # Simkl puede devolver 429 incluso en éxito, comprobaremos el cuerpo
        if response.status_code == 429:
            try:
                data = response.json()
                if data.get("message") == "Success!":
                    logger.info("Simkl returned 429 but reported success.")
                    return
            except json.JSONDecodeError:
                pass  # no es JSON, continuar como error
        response.raise_for_status()
        logger.info("Simkl history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)
    except Exception as e:
        logger.error("Failed to update Simkl: %s", e)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)


# --------------------------------------------------------------------------- #
# PLEX ↔ TRAKT
# --------------------------------------------------------------------------- #

def get_trakt_history_basic(
    headers: dict,
) -> Tuple[
    Dict[str, Tuple[str, Optional[int]]],
    Dict[str, Tuple[str, str]],
]:
    """Return Trakt history keyed by IMDb/TMDb GUID for movies and episodes."""
    movies: Dict[str, Tuple[str, Optional[int]]] = {}
    episodes: Dict[str, Tuple[str, str]] = {}

    page = 1
    logger.info("Fetching Trakt history…")
    while True:
        resp = trakt_request(
            "GET",
            "/sync/history",
            headers,
            params={"page": page, "limit": 100},
        )
        data = resp.json()
        if not isinstance(data, list):
            logger.error("Unexpected Trakt history format: %r", data)
            break
        if not data:
            break
        for item in data:
            if item["type"] == "movie":
                m = item["movie"]
                ids = m.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in movies:
                    year = int(m["year"]) if m.get("year") else None
                    movies[guid] = (m["title"], year)
            elif item["type"] == "episode":
                e = item["episode"]
                show = item["show"]
                ids = e.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in episodes:
                    episodes[guid] = (
                        show["title"],
                        f"S{e['season']:02d}E{e['number']:02d}",
                    )
        page += 1

    return movies, episodes


def update_trakt(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Send watched history to Trakt."""
    payload = {"movies": [], "episodes": []}

    # Movies
    for title, year, watched_at, guid in movies:
        movie_obj = {"title": title}
        if year is not None:
            movie_obj["year"] = year
        if guid:
            movie_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            movie_obj["watched_at"] = watched_at
        payload["movies"].append(movie_obj)

    # Episodes
    for show, code, watched_at, guid in episodes:
        try:
            season = int(code[1:3])
            number = int(code[4:6])
        except (ValueError, IndexError):
            logger.warning("Invalid episode code format: %s", code)
            continue
            
        ep_obj = {"season": season, "number": number}
        if guid:
            ep_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            ep_obj["watched_at"] = watched_at
        payload["episodes"].append(ep_obj)

    if not payload["movies"] and not payload["episodes"]:
        logger.info("Nothing new to send to Trakt.")
        return

    logger.info(
        "Sent %d movies and %d episodes to Trakt",
        len(payload["movies"]),
        len(payload["episodes"]),
    )
    try:
        trakt_request("POST", "/sync/history", headers, json=payload)
        logger.info("Trakt history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Trakt history: %s", e)


def update_simkl(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Add new items to Simkl history con búsqueda de IDs de respaldo."""
    payload = {}
    if movies:
        payload["movies"] = []
        for title, year, guid, watched_at in movies:
            item = {"title": title, "year": normalize_year(year)}
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, title, is_movie=True, year=year)
                if ids:
                    logger.debug("IDs found in Simkl for movie '%s': %s", title, ids)
            if ids:
                item["ids"] = ids
            if watched_at:
                item["watched_at"] = watched_at
            payload["movies"].append(item)

    if episodes:
        shows: Dict[str, dict] = {}
        for show_title, code, guid, watched_at in episodes:
            # Intentar obtener IDs de la serie
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, show_title, is_movie=False)
                if ids:
                    logger.debug("IDs found in Simkl for show '%s': %s", show_title, ids)
            if not ids:
                logger.warning(
                    "Skipping episode '%s - %s' - no IDs found", show_title, code
                )
                continue

            key = tuple(sorted(ids.items()))  # clave única para la serie
            if key not in shows:
                shows[key] = {
                    "title": show_title,
                    "ids": ids,
                    "seasons": [],
                }

            try:
                season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
            except ValueError:
                logger.warning("Invalid episode code format: %s", code)
                continue

            season_found = False
            for s in shows[key]["seasons"]:
                if s["number"] == season_num:
                    s["episodes"].append({"number": episode_num, "watched_at": watched_at})
                    season_found = True
                    break

            if not season_found:
                shows[key]["seasons"].append(
                    {
                        "number": season_num,
                        "episodes": [{"number": episode_num, "watched_at": watched_at}],
                    }
                )
        if shows:
            payload["shows"] = list(shows.values())

    if not payload:
        logger.info("Nothing new to sync with Simkl")
        return

    logger.info(
        "Adding %d movies and %d shows to Simkl history",
        len(payload.get("movies", [])),
        len(payload.get("shows", [])),
    )
    try:
        response = simkl_request(
            "post", "/sync/history", headers, json=payload
        )
        # Simkl puede devolver 429 incluso en éxito, comprobaremos el cuerpo
        if response.status_code == 429:
            try:
                data = response.json()
                if data.get("message") == "Success!":
                    logger.info("Simkl returned 429 but reported success.")
                    return
            except json.JSONDecodeError:
                pass  # no es JSON, continuar como error
        response.raise_for_status()
        logger.info("Simkl history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)
    except Exception as e:
        logger.error("Failed to update Simkl: %s", e)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)


# --------------------------------------------------------------------------- #
# PLEX ↔ TRAKT
# --------------------------------------------------------------------------- #

def get_trakt_history_basic(
    headers: dict,
) -> Tuple[
    Dict[str, Tuple[str, Optional[int]]],
    Dict[str, Tuple[str, str]],
]:
    """Return Trakt history keyed by IMDb/TMDb GUID for movies and episodes."""
    movies: Dict[str, Tuple[str, Optional[int]]] = {}
    episodes: Dict[str, Tuple[str, str]] = {}

    page = 1
    logger.info("Fetching Trakt history…")
    while True:
        resp = trakt_request(
            "GET",
            "/sync/history",
            headers,
            params={"page": page, "limit": 100},
        )
        data = resp.json()
        if not isinstance(data, list):
            logger.error("Unexpected Trakt history format: %r", data)
            break
        if not data:
            break
        for item in data:
            if item["type"] == "movie":
                m = item["movie"]
                ids = m.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in movies:
                    year = int(m["year"]) if m.get("year") else None
                    movies[guid] = (m["title"], year)
            elif item["type"] == "episode":
                e = item["episode"]
                show = item["show"]
                ids = e.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in episodes:
                    episodes[guid] = (
                        show["title"],
                        f"S{e['season']:02d}E{e['number']:02d}",
                    )
        page += 1

    return movies, episodes


def update_trakt(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Send watched history to Trakt."""
    payload = {"movies": [], "episodes": []}

    # Movies
    for title, year, watched_at, guid in movies:
        movie_obj = {"title": title}
        if year is not None:
            movie_obj["year"] = year
        if guid:
            movie_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            movie_obj["watched_at"] = watched_at
        payload["movies"].append(movie_obj)

    # Episodes
    for show, code, watched_at, guid in episodes:
        try:
            season = int(code[1:3])
            number = int(code[4:6])
        except (ValueError, IndexError):
            logger.warning("Invalid episode code format: %s", code)
            continue
            
        ep_obj = {"season": season, "number": number}
        if guid:
            ep_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            ep_obj["watched_at"] = watched_at
        payload["episodes"].append(ep_obj)

    if not payload["movies"] and not payload["episodes"]:
        logger.info("Nothing new to send to Trakt.")
        return

    logger.info(
        "Sent %d movies and %d episodes to Trakt",
        len(payload["movies"]),
        len(payload["episodes"]),
    )
    try:
        trakt_request("POST", "/sync/history", headers, json=payload)
        logger.info("Trakt history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Trakt history: %s", e)


def update_simkl(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Add new items to Simkl history con búsqueda de IDs de respaldo."""
    payload = {}
    if movies:
        payload["movies"] = []
        for title, year, guid, watched_at in movies:
            item = {"title": title, "year": normalize_year(year)}
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, title, is_movie=True, year=year)
                if ids:
                    logger.debug("IDs found in Simkl for movie '%s': %s", title, ids)
            if ids:
                item["ids"] = ids
            if watched_at:
                item["watched_at"] = watched_at
            payload["movies"].append(item)

    if episodes:
        shows: Dict[str, dict] = {}
        for show_title, code, guid, watched_at in episodes:
            # Intentar obtener IDs de la serie
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, show_title, is_movie=False)
                if ids:
                    logger.debug("IDs found in Simkl for show '%s': %s", show_title, ids)
            if not ids:
                logger.warning(
                    "Skipping episode '%s - %s' - no IDs found", show_title, code
                )
                continue

            key = tuple(sorted(ids.items()))  # clave única para la serie
            if key not in shows:
                shows[key] = {
                    "title": show_title,
                    "ids": ids,
                    "seasons": [],
                }

            try:
                season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
            except ValueError:
                logger.warning("Invalid episode code format: %s", code)
                continue

            season_found = False
            for s in shows[key]["seasons"]:
                if s["number"] == season_num:
                    s["episodes"].append({"number": episode_num, "watched_at": watched_at})
                    season_found = True
                    break

            if not season_found:
                shows[key]["seasons"].append(
                    {
                        "number": season_num,
                        "episodes": [{"number": episode_num, "watched_at": watched_at}],
                    }
                )
        if shows:
            payload["shows"] = list(shows.values())

    if not payload:
        logger.info("Nothing new to sync with Simkl")
        return

    logger.info(
        "Adding %d movies and %d shows to Simkl history",
        len(payload.get("movies", [])),
        len(payload.get("shows", [])),
    )
    try:
        response = simkl_request(
            "post", "/sync/history", headers, json=payload
        )
        # Simkl puede devolver 429 incluso en éxito, comprobaremos el cuerpo
        if response.status_code == 429:
            try:
                data = response.json()
                if data.get("message") == "Success!":
                    logger.info("Simkl returned 429 but reported success.")
                    return
            except json.JSONDecodeError:
                pass  # no es JSON, continuar como error
        response.raise_for_status()
        logger.info("Simkl history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)
    except Exception as e:
        logger.error("Failed to update Simkl: %s", e)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)


# --------------------------------------------------------------------------- #
# PLEX ↔ TRAKT
# --------------------------------------------------------------------------- #

def get_trakt_history_basic(
    headers: dict,
) -> Tuple[
    Dict[str, Tuple[str, Optional[int]]],
    Dict[str, Tuple[str, str]],
]:
    """Return Trakt history keyed by IMDb/TMDb GUID for movies and episodes."""
    movies: Dict[str, Tuple[str, Optional[int]]] = {}
    episodes: Dict[str, Tuple[str, str]] = {}

    page = 1
    logger.info("Fetching Trakt history…")
    while True:
        resp = trakt_request(
            "GET",
            "/sync/history",
            headers,
            params={"page": page, "limit": 100},
        )
        data = resp.json()
        if not isinstance(data, list):
            logger.error("Unexpected Trakt history format: %r", data)
            break
        if not data:
            break
        for item in data:
            if item["type"] == "movie":
                m = item["movie"]
                ids = m.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in movies:
                    year = int(m["year"]) if m.get("year") else None
                    movies[guid] = (m["title"], year)
            elif item["type"] == "episode":
                e = item["episode"]
                show = item["show"]
                ids = e.get("ids", {})
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                else:
                    guid = None
                if not guid:
                    continue
                if guid not in episodes:
                    episodes[guid] = (
                        show["title"],
                        f"S{e['season']:02d}E{e['number']:02d}",
                    )
        page += 1

    return movies, episodes


def update_trakt(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Send watched history to Trakt."""
    payload = {"movies": [], "episodes": []}

    # Movies
    for title, year, watched_at, guid in movies:
        movie_obj = {"title": title}
        if year is not None:
            movie_obj["year"] = year
        if guid:
            movie_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            movie_obj["watched_at"] = watched_at
        payload["movies"].append(movie_obj)

    # Episodes
    for show, code, watched_at, guid in episodes:
        try:
            season = int(code[1:3])
            number = int(code[4:6])
        except (ValueError, IndexError):
            logger.warning("Invalid episode code format: %s", code)
            continue
            
        ep_obj = {"season": season, "number": number}
        if guid:
            ep_obj["ids"] = guid_to_ids(guid)
        if watched_at:
            ep_obj["watched_at"] = watched_at
        payload["episodes"].append(ep_obj)

    if not payload["movies"] and not payload["episodes"]:
        logger.info("Nothing new to send to Trakt.")
        return

    logger.info(
        "Sent %d movies and %d episodes to Trakt",
        len(payload["movies"]),
        len(payload["episodes"]),
    )
    try:
        trakt_request("POST", "/sync/history", headers, json=payload)
        logger.info("Trakt history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Trakt history: %s", e)


def update_simkl(
    headers: dict,
    movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]],
    episodes: List[Tuple[str, str, Optional[str], Optional[str]]],
) -> None:
    """Add new items to Simkl history con búsqueda de IDs de respaldo."""
    payload = {}
    if movies:
        payload["movies"] = []
        for title, year, guid, watched_at in movies:
            item = {"title": title, "year": normalize_year(year)}
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, title, is_movie=True, year=year)
                if ids:
                    logger.debug("IDs found in Simkl for movie '%s': %s", title, ids)
            if ids:
                item["ids"] = ids
            if watched_at:
                item["watched_at"] = watched_at
            payload["movies"].append(item)

    if episodes:
        shows: Dict[str, dict] = {}
        for show_title, code, guid, watched_at in episodes:
            # Intentar obtener IDs de la serie
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, show_title, is_movie=False)
                if ids:
                    logger.debug("IDs found in Simkl for show '%s': %s", show_title, ids)
            if not ids:
                logger.warning(
                    "Skipping episode '%s - %s' - no IDs found", show_title, code
                )
                continue

            key = tuple(sorted(ids.items()))  # clave única para la serie
            if key not in shows:
                shows[key] = {
                    "title": show_title,
                    "ids": ids,
                    "seasons": [],
                }

            try:
                season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
            except ValueError:
                logger.warning("Invalid episode code format: %s", code)
                continue

            season_found = False
            for s in shows[key]["seasons"]:
                if s["number"] == season_num:
                    s["episodes"].append({"number": episode_num, "watched_at": watched_at})
                    season_found = True
                    break

            if not season_found:
                shows[key]["seasons"].append(
                    {
                        "number": season_num,
                        "episodes": [{"number": episode_num, "watched_at": watched_at}],
                    }
                )
        if shows:
            payload["shows"] = list(shows.values())

    if not payload:
        logger.info("Nothing new to sync with Simkl")
        return

    logger.info(
        "Adding %d movies and %d shows to Simkl history",
        len(payload.get("movies", [])),
        len(payload.get("shows", [])),
    )
    try:
        response = simkl_request(
            "post", "/sync/history", headers, json=payload
        )
        # Simkl puede devolver 429 incluso en éxito, comprobaremos el cuerpo
        if response.status_code == 429:
            try:
                data = response.json()
                if data.get("message") == "Success!":
                    logger.info("Simkl returned 429 but reported success.")
                    return
            except json.JSONDecodeError:
                pass  # no es JSON, continuar como error
        response.raise_for_status()
        logger.info("Simkl history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)
    except Exception as e:
        logger.error("Failed to update Simkl: %s", e)
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)


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

def sync():
    """Run the main synchronization logic with selected user."""
    # Reset cache to ensure fresh data on every sync start
    reset_cache()
    
    if not test_connections():
        logger.error("Sync cancelled due to connection errors.")
        return

    # Check if a user is selected for sync
    selected_user = load_selected_user()
    if not selected_user:
        logger.error("No user selected for sync. Please select a user first.")
        return

    logger.info("Starting sync for user: %s (%s)", selected_user["username"], selected_user["role"])
    
    # Validate bidirectional sync configuration
    validate_bidirectional_sync_config()
    
    trakt_enabled = os.path.exists(TOKEN_FILE)
    simkl_enabled = os.path.exists(SIMKL_TOKEN_FILE)

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
        load_simkl_tokens()
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
        if SYNC_PROVIDER == "trakt":
            logger.info("Provider: Trakt")
            last_sync = load_trakt_last_sync_date()
            current_activity = get_trakt_last_activity(headers)
            if last_sync and current_activity and current_activity == last_sync:
                logger.info("No new Trakt activity since %s", last_sync)
                trakt_movies, trakt_episodes = {}, {}
            else:
                try:
                    trakt_movies, trakt_episodes = get_trakt_history(
                        headers, date_from=last_sync
                    )
                except Exception as exc:
                    logger.error("Failed to retrieve Trakt history: %s", exc)
                    trakt_movies, trakt_episodes = {}, {}
            
            # Always do full sync with Plex - get all history without date filtering
            plex_movies, plex_episodes = get_selected_user_history()
            logger.info("Found %d movies and %d episodes in Plex history (full sync).",
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

            if SYNC_WATCHED:
                try:
                    update_trakt(headers, new_movies, new_episodes)
                except Exception as exc:
                    logger.error("Failed updating Trakt history: %s", exc)

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
            if selected_user.get("is_owner", False):
                if missing_movies or missing_episodes:
                    start_time = time.time()
                    logger.info("Bidirectional sync: Marking %d movies and %d episodes as watched for user %s (%s)", 
                               len(missing_movies), len(missing_episodes), 
                               selected_user["username"], selected_user["role"])
                    
                    # Batch process movies - collect results first
                    movie_start = time.time()
                    movie_results = []
                    for title, year, guid in missing_movies:
                        try:
                            if mark_as_watched_for_user(guid, "movie", selected_user):
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
                        try:
                            if mark_as_watched_for_user(guid, "episode", selected_user):
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
            else:
                if missing_movies or missing_episodes:
                    logger.info("Skipping bidirectional sync for managed user %s: %d movies and %d episodes would have been synced from Trakt to Plex", 
                               selected_user["username"], len(missing_movies), len(missing_episodes))

            if SYNC_LIKED_LISTS:
                try:
                    sync_liked_lists(plex, headers)
                    sync_collections_to_trakt(plex, headers)
                except TraktAccountLimitError as exc:
                    logger.error("Liked-lists sync skipped: %s", exc)
                except Exception as exc:
                    logger.error("Liked-lists sync failed: %s", exc)
            if SYNC_WATCHLISTS:
                try:
                    sync_watchlist(
                        plex,
                        headers,
                        plex_movie_guids | plex_episode_guids,
                        trakt_movie_guids | trakt_episode_guids,
                    )
                except TraktAccountLimitError as exc:
                    logger.error("Watchlist sync skipped: %s", exc)
                except Exception as exc:
                    logger.error("Watchlist sync failed: %s", exc)

            if current_activity:
                save_trakt_last_sync_date(current_activity)

        elif SYNC_PROVIDER == "simkl":
            logger.info("Provider: Simkl")
            last_sync = load_last_sync_date()
            current_activity = get_last_activity(headers)
            if last_sync and current_activity and current_activity == last_sync:
                logger.info("No new Simkl activity since %s", last_sync)
                simkl_movies, simkl_episodes = {}, {}
            else:
                simkl_movies, simkl_episodes = get_simkl_history(
                    headers, date_from=last_sync
                )
                logger.info(
                    "Retrieved %d movies and %d episodes from Simkl",
                    len(simkl_movies),
                    len(simkl_episodes),
                )
            
            # Always do full sync with Plex - get all history without date filtering
            plex_movies, plex_episodes = get_selected_user_history()
            logger.info("Found %d movies and %d episodes in Plex history (full sync).",
                       len(plex_movies), len(plex_episodes))

            # Always do full sync for Plex -> Simkl: sync all items from Plex
            # This ensures reliable episode detection without timestamp comparison issues
            movies_to_add = set(plex_movies)
            episodes_to_add = set(plex_episodes)

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
            # Para cada episodio necesitamos el GUID de la SERIE (no el del episodio) para que Simkl pueda identificarla correctamente.
            episodes_to_add_fmt = []
            for e in episodes_to_add:
                ep_info = plex_episodes[e]
                show_title = ep_info["show"]
                code = ep_info["code"]
                watched_at = ep_info.get("watched_at")

                # Intentamos obtener la serie desde la biblioteca de Plex para extraer un GUID válido (imdb/tmdb/tvdb) a nivel de serie.
                show_guid = None
                try:
                    show_obj = get_show_from_library(plex, show_title)
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
            
            if movies_to_add_fmt or episodes_to_add_fmt:
                update_simkl(headers, movies_to_add_fmt, episodes_to_add_fmt)

            # Plex <- Simkl (only for owner users)
            if selected_user.get("is_owner", False):
                movies_to_add_plex = set(simkl_movies) - set(plex_movies)
                episodes_to_add_plex = set(simkl_episodes) - set(plex_episodes)
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
                    update_plex(plex, movies_to_add_plex_fmt, episodes_to_add_plex_fmt)
            else:
                movies_to_add_plex = set(simkl_movies) - set(plex_movies)
                episodes_to_add_plex = set(simkl_episodes) - set(plex_episodes)
                if movies_to_add_plex or episodes_to_add_plex:
                    logger.info("Skipping bidirectional sync for managed user %s: %d movies and %d episodes would have been synced from Simkl to Plex", 
                               selected_user["username"], len(movies_to_add_plex), len(episodes_to_add_plex))

            if current_activity:
                save_last_sync_date(current_activity)

    except Exception as exc:  # noqa: BLE001
        logger.error("Error during sync: %s", exc)

    # Sincronizar valoraciones solo es compatible con Trakt por ahora
    if SYNC_RATINGS and SYNC_PROVIDER == "trakt":
        sync_ratings(plex, headers)
    elif SYNC_RATINGS and SYNC_PROVIDER == "simkl":
        logger.warning("Ratings sync with Simkl is not yet supported.")

    if SYNC_WATCHLISTS and SYNC_PROVIDER == "trakt":
        sync_watchlist(plex, headers, plex_movies, trakt_movies)
    elif SYNC_WATCHLISTS and SYNC_PROVIDER == "simkl":
        logger.warning("Watchlist sync with Simkl is not yet supported.")

    if SYNC_COLLECTION:
        sync_collection(plex, headers)

    if SYNC_LIKED_LISTS and SYNC_PROVIDER == "trakt":
        sync_liked_lists(plex, headers)
    elif SYNC_LIKED_LISTS and SYNC_PROVIDER == "simkl":
        logger.warning("Liked lists sync with Simkl is not yet supported.")

    if SYNC_PROVIDER == "trakt":
        sync_collections_to_trakt(plex, headers)
    elif SYNC_PROVIDER == "simkl":
        logger.warning("Plex Collections sync to Simkl is not yet supported.")

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
@app.route("/", methods=["GET", "POST"])
def index():
    global SYNC_INTERVAL_MINUTES, SYNC_COLLECTION, SYNC_RATINGS, SYNC_WATCHED, SYNC_LIKED_LISTS, SYNC_WATCHLISTS, LIVE_SYNC

    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()

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

        # Check if a managed user is selected and restrict options
        selected_user = load_selected_user()
        if selected_user and not selected_user.get("is_owner", False):
            # For managed users, disable restricted sync options regardless of form input
            SYNC_COLLECTION = False
            SYNC_RATINGS = False
            SYNC_LIKED_LISTS = False
            SYNC_WATCHLISTS = False
            LIVE_SYNC = False
            logger.info("Restricted sync options disabled for managed user: %s", selected_user.get("username", "Unknown"))

        if SYNC_PROVIDER == "simkl":
            SYNC_COLLECTION = False
            SYNC_RATINGS = False
            SYNC_LIKED_LISTS = False
            SYNC_WATCHLISTS = False
            LIVE_SYNC = False
        
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
    
    # Check if a managed user is selected and adjust sync options for display
    selected_user = load_selected_user()
    display_collection = SYNC_COLLECTION
    display_ratings = SYNC_RATINGS
    display_liked_lists = SYNC_LIKED_LISTS
    display_watchlists = SYNC_WATCHLISTS
    display_live_sync = LIVE_SYNC
    
    if selected_user and not selected_user.get("is_owner", False):
        # For managed users, show these options as unchecked/disabled
        display_collection = False
        display_ratings = False
        display_liked_lists = False
        display_watchlists = False
        display_live_sync = False
    
    return render_template(
        "index.html",
        minutes=SYNC_INTERVAL_MINUTES,
        collection=display_collection,
        ratings=display_ratings,
        watched=SYNC_WATCHED,
        liked_lists=display_liked_lists,
        watchlists=display_watchlists,
        live_sync=display_live_sync,
        provider=SYNC_PROVIDER,
        message=message,
        mtype=mtype,
        next_run=next_run,
    )


@app.route("/oauth")
def oauth_index():
    """Landing page for OAuth callbacks."""
    return render_template("oauth.html", service=None, code=None)


@app.route("/oauth/<service>")
def oauth_callback(service: str):
    """Display OAuth code for the given service."""
    service = service.lower()
    if service not in {"trakt", "simkl"}:
        return redirect(url_for("oauth_index"))
    code = request.args.get("code", "")
    return render_template(
        "oauth.html",
        service=service.capitalize(),
        code=code,
    )


@app.route("/trakt")
def trakt_callback():
    code = request.args.get("code", "")
    return redirect(url_for("oauth_callback", service="trakt", code=code))


@app.route("/simkl")
def simkl_callback():
    code = request.args.get("code", "")
    return redirect(url_for("oauth_callback", service="simkl", code=code))


@app.route("/config", methods=["GET", "POST"])
def config_page():
    """Display configuration status for Trakt and Simkl."""
    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()
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


@app.route("/authorize/<service>", methods=["GET", "POST"])
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
def clear_service(service: str):
    """Remove stored tokens for the given service."""
    service = service.lower()
    if service == "trakt":
        os.environ.pop("TRAKT_ACCESS_TOKEN", None)
        os.environ.pop("TRAKT_REFRESH_TOKEN", None)
        if os.path.exists(TOKEN_FILE):
            try:
                os.remove(TOKEN_FILE)
                logger.info("Removed Trakt token file")
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to remove Trakt token file: %s", exc)
        if SYNC_PROVIDER == "trakt":
            save_provider("none")
    elif service == "simkl":
        os.environ.pop("SIMKL_ACCESS_TOKEN", None)
        if os.path.exists(SIMKL_TOKEN_FILE):
            try:
                os.remove(SIMKL_TOKEN_FILE)
                logger.info("Removed Simkl token file")
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to remove Simkl token file: %s", exc)
        if SYNC_PROVIDER == "simkl":
            save_provider("none")
    return redirect(url_for("config_page"))


@app.route("/stop", methods=["POST"])
def stop():
    stop_scheduler()
    return redirect(
        url_for("index", message="Sync stopped successfully!", mtype="stopped")
    )


@app.route("/reset_timestamps", methods=["POST"])
def reset_timestamps():
    """Reset sync timestamps to force a full sync on next run."""
    try:
        timestamps_reset = reset_sync_timestamps()
        
        if timestamps_reset:
            message = f"Timestamps reset for {', '.join(timestamps_reset)}. Next sync will be a full sync."
        else:
            message = "No timestamps found to reset."
            
        logger.info("Timestamps reset by user. Files removed: %s", timestamps_reset)
        
        return redirect(
            url_for("index", message=message, mtype="success")
        )
    except Exception as exc:
        logger.error("Failed to reset timestamps: %s", exc)
        return redirect(
            url_for("index", message="Failed to reset timestamps. Check logs for details.", mtype="error")
        )


@app.route("/backup")
def backup_page():
    message = request.args.get("message")
    mtype = request.args.get("mtype", "success") if message else None
    return render_template("backup.html", message=message, mtype=mtype)


@app.route("/backup/download")
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


@app.route("/users")
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
        if code:
            session['plex_2fa_code'] = code
        session['plex_account_id'] = account.id
        session['plex_username'] = account.username
        
        # Also save credentials for scheduler access (including token to avoid 2FA re-auth)
        save_session_credentials(email, password, code, account.authToken)
        
        # Reset global Plex variables to force re-authentication with new credentials
        global plex, plex_account
        plex = None
        plex_account = account
        
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
    """Clear all session data and log out the user."""
    session.clear()
    # Also clear global session credentials
    clear_session_credentials()
    # Reset global Plex variables
    global plex, plex_account
    plex = None
    plex_account = None
    return jsonify({"success": True, "message": "Successfully logged out"})


# --------------------------------------------------------------------------- #
# SCHEDULER STARTUP
# --------------------------------------------------------------------------- #
def test_connections() -> bool:
    global plex
    # Check session first, then fall back to environment variables
    from flask import has_request_context, session
    
    plex_email = None
    plex_password = None
    plex_token = None
    
    if has_request_context():
        plex_email = session.get('plex_email')
        plex_password = session.get('plex_password')
        plex_token = session.get('plex_token')
    
    # If not in request context or session empty, check global session credentials
    if not plex_token and (not plex_email or not plex_password):
        plex_email, plex_password, _, plex_token, _ = get_session_credentials()
    
    # Fall back to environment variables if session data not available
    if not plex_token and (not plex_email or not plex_password):
        plex_email = os.environ.get("PLEX_EMAIL")
        plex_password = os.environ.get("PLEX_PASSWORD")
    
    plex_baseurl = os.environ.get("PLEX_BASEURL")
    plex_env_token = os.environ.get("PLEX_TOKEN")
    
    # Use environment token only if no session token is available
    if not plex_token and plex_env_token:
        plex_token = plex_env_token
    
    trakt_token = os.environ.get("TRAKT_ACCESS_TOKEN")
    trakt_client_id = os.environ.get("TRAKT_CLIENT_ID")
    trakt_enabled = SYNC_PROVIDER == "trakt" and bool(trakt_token and trakt_client_id)
    simkl_token = os.environ.get("SIMKL_ACCESS_TOKEN")
    simkl_client_id = os.environ.get("SIMKL_CLIENT_ID")
    simkl_enabled = SYNC_PROVIDER == "simkl" and bool(simkl_token and simkl_client_id)

    # Check if we have any form of authentication
    has_token = bool(plex_token)
    has_credentials = bool(plex_email and plex_password)
    has_legacy = bool(plex_baseurl and plex_token)
    
    if not has_token and not has_credentials and not has_legacy:
        logger.error("Missing Plex authentication. Provide either session credentials, PLEX_EMAIL/PLEX_PASSWORD or PLEX_BASEURL/PLEX_TOKEN.")
        return False
    if not trakt_enabled and not simkl_enabled:
        logger.error("Missing environment variables for selected provider.")
        return False

    try:
        plex = get_plex_server()
        if plex is None:
            return False
        # Test connection by accessing server account info
        plex.account()
        logger.info("Successfully connected to Plex server.")
    except Exception as exc:
        logger.error("Failed to connect to Plex: %s", exc)
        plex = None
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
    scheduler.add_job(
        sync,
        "interval",
        minutes=SYNC_INTERVAL_MINUTES,
        id="sync_job",
        replace_existing=True,
    )
    logger.info("Sync job scheduled with interval %d minutes", SYNC_INTERVAL_MINUTES)


def stop_scheduler():
    """Detiene y elimina el job de sincronización dejando el scheduler limpio."""
    global scheduler
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
SELECTED_USER_FILE = "selected_user.json"

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
    """Get history for the currently selected user. Always performs full sync for reliability."""
    selected_user = load_selected_user()
    if not selected_user:
        logger.warning("No user selected for sync")
        return {}, {}
    
    account = get_plex_account()
    if not account:
        logger.error("No Plex account available")
        return {}, {}
    
    # Always do full sync for Plex (ignore mindate) to ensure reliable episode detection
    if selected_user["is_owner"]:
        logger.debug("Getting full history for owner (full sync)")
        return get_owner_plex_history(account, mindate=None)
    else:
        logger.debug("Getting full history for managed user %s (full sync)", selected_user["username"])
        return get_managed_user_plex_history(account, selected_user["id"], mindate=None)

# Cache for users to avoid repeated API calls
_cached_users = None
_cached_users_timestamp = None
CACHE_DURATION = 300  # 5 minutes

def reset_cache():
    """Reset all cached data to ensure fresh data on sync start"""
    global _cached_users, _cached_users_timestamp
    _cached_users = None
    _cached_users_timestamp = None
    
    # Reset sections cache from utils.py
    from utils import reset_sections_cache
    reset_sections_cache()
    
    # Reset movie and show GUID caches from plex_utils.py
    from plex_utils import reset_movie_guid_cache, reset_show_guid_cache
    reset_movie_guid_cache()
    reset_show_guid_cache()
    
    logger.debug("Cache reset - all cached data cleared (users, sections, movie GUIDs, and show GUIDs)")

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

def mark_as_watched_for_user(item_guid, item_type, user_data):
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
            logger.debug("Item not found in Plex: %s (type: %s) - search took %.2fs", item_guid, item_type, search_duration)
            return False
        
        # Validate item type matches expectation
        actual_type = getattr(item, 'TYPE', 'unknown')
        if item_type == "movie" and actual_type != "movie":
            logger.warning("Type mismatch: expected movie but found %s for %s", actual_type, item.title)
        elif item_type == "episode" and actual_type != "episode":
            logger.warning("Type mismatch: expected episode but found %s for %s", actual_type, item.title)
            
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
                            # Connect to server with managed user account
                            user_plex = user_account.resource(plex_server.friendlyName).connect()
                            
                            # Find the item from the managed user's perspective
                            user_item = find_item_by_guid(user_plex, item_guid)
                            if user_item:
                                user_item.markWatched()
                                logger.info("Marked %s as watched for managed user %s: %s", 
                                           item_type, user_data["username"], item.title)
                                return True
                            else:
                                # Alternative: mark as watched from main server for this user
                                logger.warning("Item not accessible from managed user perspective, marking via main server")
                                item.markWatched()
                                logger.info("Marked %s as watched for managed user %s via main server: %s", 
                                           item_type, user_data["username"], item.title)
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

def reset_sync_timestamps():
    """Reset sync timestamps to ensure clean state when switching users."""
    try:
        # Import the timestamp file constants
        from trakt_utils import TRAKT_LAST_SYNC_FILE
        from simkl_utils import SIMKL_LAST_SYNC_FILE
        from plex_utils import PLEX_LAST_SYNC_FILE
        
        # Remove timestamp files if they exist
        timestamps_reset = []
        
        if os.path.exists(TRAKT_LAST_SYNC_FILE):
            os.remove(TRAKT_LAST_SYNC_FILE)
            timestamps_reset.append("Trakt")
            
        if os.path.exists(SIMKL_LAST_SYNC_FILE):
            os.remove(SIMKL_LAST_SYNC_FILE)
            timestamps_reset.append("Simkl")
            
        if os.path.exists(PLEX_LAST_SYNC_FILE):
            os.remove(PLEX_LAST_SYNC_FILE)
            timestamps_reset.append("Plex")
        
        logger.info("Sync timestamps reset for user switch. Files removed: %s", timestamps_reset)
        return timestamps_reset
        
    except Exception as exc:
        logger.error("Failed to reset sync timestamps: %s", exc)
        return []

@app.route("/api/select_user", methods=["POST"])
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
            # Reset sync timestamps to prevent cross-user timestamp pollution
            timestamps_reset = reset_sync_timestamps()
            
            logger.info("Selected user for sync: %s (%s)", username, role)
            
            # Provide informative message about timestamp reset
            message = f"Selected {username} for sync"
            if timestamps_reset:
                message += f". Sync timestamps reset for clean state ({', '.join(timestamps_reset)})"
            
            return jsonify({"success": True, "message": message})
        else:
            return jsonify({"success": False, "error": "Failed to save user selection"})
            
    except Exception as exc:
        logger.error("Failed to select user: %s", exc)
        return jsonify({"success": False, "error": str(exc)})

@app.route("/api/get_selected_user")
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
def save_session_credentials(email, password, code=None, token=None, baseurl=None):
    """Save Plex credentials from session for scheduler access."""
    global session_plex_credentials
    session_plex_credentials['email'] = email
    session_plex_credentials['password'] = password
    session_plex_credentials['code'] = code
    session_plex_credentials['token'] = token
    session_plex_credentials['baseurl'] = baseurl
    logger.info("Session credentials saved for scheduler access")

def get_session_credentials():
    """Get Plex credentials from session storage."""
    global session_plex_credentials
    return (
        session_plex_credentials.get('email'),
        session_plex_credentials.get('password'),
        session_plex_credentials.get('code'),
        session_plex_credentials.get('token'),
        session_plex_credentials.get('baseurl')
    )

def clear_session_credentials():
    """Clear stored session credentials."""
    global session_plex_credentials
    session_plex_credentials = {'email': None, 'password': None, 'code': None, 'token': None, 'baseurl': None}
    logger.info("Session credentials cleared")


# --------------------------------------------------------------------------- #
# MAIN
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    logger.info("Starting PlexyTrackt application")
    load_trakt_tokens()
    load_simkl_tokens()
    load_provider()
    # Removed automatic scheduler start - only manual start from sync tab
    # start_scheduler()
    # Disable Flask's auto-reloader to avoid duplicate logs
    app.run(host="0.0.0.0", port=5030, use_reloader=False)
