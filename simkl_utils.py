import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

import requests

from utils import (
    guid_to_ids,
    normalize_year,
    simkl_episode_key,
    to_iso_z,
    find_item_by_guid,
    best_guid,
    safe_timestamp_compare,
)

logger = logging.getLogger(__name__)

APP_NAME = "PlexyTrack"
APP_VERSION = "v0.4.12"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"
CONFIG_DIR = os.environ.get("PLEXYTRACK_CONFIG_DIR", "/config")
STATE_DIR = os.environ.get("PLEXYTRACK_STATE_DIR", "/state")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
# Snapshot of the last ``/sync/activities`` payload seen during a sync, used to
# skip Simkl -> Plex pulls when a category has not changed.
ACTIVITIES_FILE = os.path.join(STATE_DIR, "simkl_activities.json")
SIMKL_LIST_STATUSES = {"plantowatch", "watching", "completed", "hold", "dropped"}


def load_auth() -> dict:
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load auth file: %s", exc)
    return {}


def save_auth(data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to save auth file: %s", exc)


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




def exchange_code_for_simkl_tokens(code: str, redirect_uri: str) -> Optional[dict]:
    client_id = os.environ.get("SIMKL_CLIENT_ID")
    client_secret = os.environ.get("SIMKL_CLIENT_SECRET")
    if not all([code, client_id, client_secret]):
        logger.error("Missing code or Simkl client credentials.")
        return None

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post("https://api.simkl.com/oauth/token", json=payload, timeout=30)
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


def simkl_request(method: str, endpoint: str, headers: dict, *, retries: int = 2, timeout: int = 30, **kwargs) -> requests.Response:
    url = f"https://api.simkl.com{endpoint}"

    headers.setdefault("User-Agent", USER_AGENT)

    if "timeout" in kwargs:
        timeout = kwargs.pop("timeout")
    attempt = 0
    while True:
        try:
            resp = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.exceptions.ReadTimeout as exc:
            if attempt >= retries:
                logger.error("Simkl ReadTimeout after %d attempts (%d s).", attempt + 1, timeout)
                raise
            attempt += 1
            timeout *= 2
            logger.warning(
                "Simkl request %s %s timed out (%s). Retrying (%d/%d) with timeout=%ds…",
                method.upper(), endpoint, exc, attempt, retries, timeout,
            )
        except requests.exceptions.RequestException:
            raise


def simkl_search_ids(headers: dict, title: str, *, is_movie: bool = True, year: Optional[int] = None) -> Dict[str, Union[str, int]]:
    endpoint = "/search/movies" if is_movie else "/search/shows"
    params = {"q": title, "limit": 1}
    if year and is_movie:
        params["year"] = year
    try:
        resp = simkl_request("GET", endpoint, headers, params=params)
        data = resp.json()
    except Exception as exc:
        logger.debug("Simkl search failed for '%s': %s", title, exc)
        return {}
    if not isinstance(data, list) or not data:
        return {}
    ids = data[0].get("ids", {}) or {}
    for k, v in list(ids.items()):
        try:
            ids[k] = int(v) if str(v).isdigit() else v
        except Exception:
            pass
    return ids


def add_items_to_simkl_list(
    headers: dict,
    *,
    movies: Optional[List[dict]] = None,
    shows: Optional[List[dict]] = None,
    target_list: str = "plantowatch",
) -> dict:
    """Add movies/shows to a Simkl list via ``/sync/add-to-list``.

    Args:
        headers: Auth headers for Simkl.
        movies: Optional list of movie objects (title/year/ids).
        shows: Optional list of show objects (title/year/ids).
        target_list: One of ``SIMKL_LIST_STATUSES``.
    """
    if target_list not in SIMKL_LIST_STATUSES:
        raise ValueError(f"Invalid target list: {target_list}")

    payload: Dict[str, list] = {}

    if movies:
        payload["movies"] = []
        for m in movies:
            item = dict(m)
            item["to"] = target_list
            payload["movies"].append(item)

    if shows:
        payload["shows"] = []
        for s in shows:
            item = dict(s)
            item["to"] = target_list
            payload["shows"].append(item)

    if not payload:
        return {}

    resp = simkl_request("POST", "/sync/add-to-list", headers, json=payload)
    if not resp.content:
        return {}
    return resp.json()


def get_simkl_watchlist(headers: dict, media_type: str = "all") -> dict:
    """Fetch Simkl watchlist/all-items data.

    ``media_type`` can be ``all``, ``movies`` or ``shows``.
    """
    media_type = media_type.lower()
    if media_type == "all":
        endpoint = "/sync/all-items"
    elif media_type in {"movies", "shows", "anime"}:
        endpoint = f"/sync/all-items/{media_type}/"
    else:
        raise ValueError(f"Invalid media_type: {media_type}")

    params = {"extended": "full", "episode_watched_at": "yes"}
    resp = simkl_request("GET", endpoint, headers, params=params)
    if not resp.content:
        return {}
    data = resp.json()
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        return {media_type: data}
    return {}


def sync_plex_watchlist_to_simkl(plex, headers: dict, target_list: str = "plantowatch") -> int:
    """Mirror Plex watchlist items into a Simkl list.

    Supports both ``PlexServer`` (via ``myPlexAccount().watchlist()``)
    and mocked objects exposing ``watchlist()`` directly.
    """
    try:
        watch_items = plex.watchlist()
    except Exception:
        account = plex.myPlexAccount()
        watch_items = account.watchlist()

    if not watch_items:
        return 0

    movies: List[dict] = []
    shows: List[dict] = []

    for item in watch_items:
        guid = best_guid(item)
        ids = guid_to_ids(guid) if guid else {}
        payload_item: Dict[str, Union[str, int, dict]] = {"title": item.title}
        year = normalize_year(getattr(item, "year", None))
        if year is not None:
            payload_item["year"] = year
        if ids:
            payload_item["ids"] = ids

        if getattr(item, "type", "") == "movie":
            movies.append(payload_item)
        elif getattr(item, "type", "") in {"show", "season", "episode"}:
            # Simkl list endpoint accepts shows.
            shows.append(payload_item)

    add_items_to_simkl_list(
        headers,
        movies=movies if movies else None,
        shows=shows if shows else None,
        target_list=target_list,
    )
    return len(movies) + len(shows)


def simkl_movie_key(m: dict) -> Optional[str]:
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


# ---------------------------------------------------------------------------
# Delta sync (incremental) via /sync/activities
# ---------------------------------------------------------------------------


def get_simkl_last_activities(headers: dict) -> Optional[dict]:
    """Return Simkl's ``/sync/activities`` payload or ``None`` on failure.

    Simkl recommends calling this first on every sync: the payload carries
    ``*_at``/status timestamps so we can pull only the categories that changed.
    The endpoint is invoked with POST as documented.
    """
    try:
        resp = simkl_request("POST", "/sync/activities", headers)
        data = resp.json()
        if isinstance(data, dict):
            return data
        logger.warning("Unexpected /sync/activities payload type: %s", type(data))
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to fetch Simkl activities: %s", exc)
        return None


def _load_saved_activities() -> dict:
    """Return the last persisted ``/sync/activities`` snapshot (or ``{}``)."""
    if os.path.exists(ACTIVITIES_FILE):
        try:
            with open(ACTIVITIES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load Simkl activities snapshot: %s", exc)
    return {}


def _save_activities(activities: dict) -> None:
    """Persist the ``/sync/activities`` snapshot to disk."""
    if not isinstance(activities, dict):
        return
    try:
        os.makedirs(os.path.dirname(ACTIVITIES_FILE), exist_ok=True)
        with open(ACTIVITIES_FILE, "w", encoding="utf-8") as f:
            json.dump(activities, f, indent=2)
        logger.debug("Saved Simkl activities snapshot to %s", ACTIVITIES_FILE)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to save Simkl activities snapshot: %s", exc)


def update_saved_activities(activities: dict) -> None:
    """Public wrapper to persist the latest activities snapshot."""
    _save_activities(activities)


def _dig(data: dict, dotted_path: str):
    """Return ``data`` navigated through a dotted ``a.b.c`` path or ``None``."""
    node = data
    for part in dotted_path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def has_simkl_category_changed(
    category_path: str, current_activities: Optional[dict] = None
) -> Tuple[bool, Optional[str]]:
    """Return ``(changed, saved_timestamp)`` for a dotted activities path.

    When ``current_activities`` is not provided we cannot prove the category is
    unchanged, so we return ``changed=True`` (fail open). When it is provided we
    compare the fresh timestamp against the saved one and only report
    ``changed=False`` if the saved timestamp is equal or newer.
    """
    saved = _load_saved_activities()
    saved_ts = _dig(saved, category_path)
    if current_activities is None:
        return True, saved_ts
    current_ts = _dig(current_activities, category_path)
    if current_ts is None or saved_ts is None:
        return True, saved_ts
    return safe_timestamp_compare(current_ts, saved_ts), saved_ts


# ---------------------------------------------------------------------------
# /sync/all-items (generic fetch + parsing, incl. hold / dropped statuses)
# ---------------------------------------------------------------------------


def get_simkl_all_items(
    headers: dict,
    media_type: Optional[str] = None,
    *,
    date_from: Optional[str] = None,
    extended: Optional[str] = None,
    episode_watched_at: bool = False,
    status: Optional[str] = None,
) -> dict:
    """Return the user's Simkl list items via ``/sync/all-items``.

    ``media_type`` restricts to ``movies``/``shows``/``anime``. ``date_from``
    enables incremental fetches, ``status`` restricts to a single list
    (``plantowatch``/``watching``/``completed``/``hold``/``dropped``). Returns
    ``{}`` for empty/``null`` responses.
    """
    if media_type in {"movies", "shows", "anime"}:
        endpoint = f"/sync/all-items/{media_type}/"
        if status in SIMKL_LIST_STATUSES:
            endpoint = f"/sync/all-items/{media_type}/{status}/"
    else:
        endpoint = "/sync/all-items"

    params: dict = {}
    if date_from:
        params["date_from"] = date_from
    if extended:
        params["extended"] = extended
    if episode_watched_at:
        params["episode_watched_at"] = "yes"

    resp = simkl_request("GET", endpoint, headers, params=params)
    if not getattr(resp, "content", b"ok"):
        return {}
    data = resp.json()
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and media_type:
        return {media_type: data}
    return {}


def parse_all_items_response(
    data: dict,
) -> Tuple[
    Dict[str, Tuple[Optional[str], Optional[int], Optional[str]]],
    Dict[object, Tuple[Optional[str], str, Optional[str]]],
]:
    """Parse an ``/sync/all-items`` payload into movie and episode maps.

    Unlike :func:`get_simkl_history` this does **not** filter by watched status,
    so callers can inspect any list (including ``hold``/``dropped``). Returns:

    - movies: ``{guid: (title, year, last_watched_at)}``
    - episodes: ``{key: (show_title, "S01E02", watched_at)}``
    """
    movies: Dict[str, Tuple[Optional[str], Optional[int], Optional[str]]] = {}
    episodes: Dict[object, Tuple[Optional[str], str, Optional[str]]] = {}

    if not isinstance(data, dict):
        return movies, episodes

    for movie_item in data.get("movies", []) or []:
        m = movie_item.get("movie", {}) or {}
        guid = simkl_movie_key(m)
        if not guid or guid in movies:
            continue
        movies[guid] = (
            m.get("title"),
            normalize_year(m.get("year")),
            movie_item.get("last_watched_at"),
        )

    for show_item in data.get("shows", []) or []:
        show = show_item.get("show", {}) or {}
        for season in show_item.get("seasons", []) or []:
            season_num = season.get("number", 0)
            for episode in season.get("episodes", []) or []:
                episode_num = episode.get("number", 0)
                e = {
                    "season": season_num,
                    "number": episode_num,
                    "ids": episode.get("ids", {}) or {},
                }
                key = simkl_episode_key(show, e)
                if not key or key in episodes:
                    continue
                episodes[key] = (
                    show.get("title"),
                    f"S{season_num:02d}E{episode_num:02d}",
                    episode.get("watched_at"),
                )

    return movies, episodes


def get_simkl_items_by_status(headers: dict, status: str) -> dict:
    """Return Simkl list items filtered to a single ``status``.

    Convenience wrapper exposing statuses such as ``hold`` and ``dropped`` that
    :func:`get_simkl_history` intentionally excludes. Returns a dict with
    ``movies`` and ``shows`` lists.
    """
    if status not in SIMKL_LIST_STATUSES:
        raise ValueError(f"Invalid Simkl list status: {status}")

    data = get_simkl_all_items(
        headers, extended="full", episode_watched_at=True
    )
    result: Dict[str, list] = {"movies": [], "shows": []}
    for movie_item in data.get("movies", []) or []:
        item_status = movie_item.get("status") or movie_item.get("list") or ""
        if item_status == status:
            result["movies"].append(movie_item)
    for show_item in data.get("shows", []) or []:
        item_status = show_item.get("status") or show_item.get("list") or ""
        if item_status == status:
            result["shows"].append(show_item)
    return result


def get_simkl_history(
    headers: dict, *, date_from: Optional[str] = None
) -> Tuple[
    Dict[str, Tuple[str, Optional[int], Optional[str]]],
    Dict[str, Tuple[str, str, Optional[str]]],
]:
    """Return Simkl movie and episode history keyed on best GUID.

    Fetches from both ``/sync/history`` (explicit watch events) and
    ``/sync/all-items`` (completed items that may lack individual history
    entries).

    Returns:
        Tuple containing:
        - Movies: Dict[guid, (title, year, watched_at)]
        - Episodes: Dict[guid, (show_title, episode_code, watched_at)]
    """
    movies: Dict[str, Tuple[str, Optional[int], Optional[str]]] = {}
    episodes: Dict[str, Tuple[str, str, Optional[str]]] = {}

    # --- /sync/history (movies) ---
    params: dict = {"type": "movies"}
    if date_from:
        params["date_from"] = date_from
    logger.info("Fetching Simkl watch history…")
    resp = simkl_request("GET", "/sync/history", headers, params=params)
    data = resp.json()
    if isinstance(data, list):
        for item in data:
            m = item.get("movie", {})
            guid = simkl_movie_key(m)
            if not guid:
                continue
            if guid not in movies:
                movies[guid] = (m.get("title"), normalize_year(m.get("year")), item.get("watched_at"))

    # --- /sync/history (episodes) ---
    params = {"type": "episodes"}
    if date_from:
        params["date_from"] = date_from
    logger.info("Fetching Simkl episode history…")
    resp = simkl_request("GET", "/sync/history", headers, params=params)
    data = resp.json()
    if isinstance(data, list):
        for item in data:
            e = item.get("episode", {})
            show = item.get("show", {})
            guid = simkl_episode_key(show, e)
            if not guid:
                continue
            if guid not in episodes:
                episodes[guid] = (show.get("title"), f"S{e.get('season', 0):02d}E{e.get('number', 0):02d}", item.get("watched_at"))

    # --- /sync/all-items (completed movies & shows with episodes) ---
    logger.info("Fetching Simkl all-items (full)…")
    resp = simkl_request(
        "GET",
        "/sync/all-items",
        headers,
        params={"extended": "full", "episode_watched_at": "yes"},
    )
    data = resp.json()
    if data and isinstance(data, dict):
        # Only include movies that are actually watched (completed/watching).
        # The /sync/all-items endpoint returns ALL list statuses including
        # "plantowatch", "hold", and "dropped" which must be excluded to
        # avoid incorrectly marking unwatched items as watched in Plex.
        _WATCHED_STATUSES = {"completed", "watching"}
        all_movies = data.get("movies", [])
        for movie_item in all_movies:
            item_status = movie_item.get("status") or movie_item.get("list") or ""
            if item_status not in _WATCHED_STATUSES:
                continue
            m = movie_item.get("movie", {})
            guid = simkl_movie_key(m)
            if not guid:
                continue
            if guid not in movies:
                watched_at = movie_item.get("last_watched_at")
                movies[guid] = (
                    m.get("title"),
                    normalize_year(m.get("year")),
                    watched_at,
                )

        # Only include episodes from shows that are completed or watching
        all_shows = data.get("shows", [])
        for show_item in all_shows:
            item_status = show_item.get("status") or show_item.get("list") or ""
            if item_status not in _WATCHED_STATUSES:
                continue
            show = show_item.get("show", {})
            seasons = show_item.get("seasons", [])
            for season in seasons:
                season_num = season.get("number", 0)
                season_episodes = season.get("episodes", [])
                for episode in season_episodes:
                    if not (
                        episode.get("watched_at")
                        or episode.get("plays", 0) > 0
                        or episode.get("watched")
                    ):
                        continue

                    episode_num = episode.get("number", 0)
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


def update_simkl(headers: dict, movies: List[Tuple[str, Optional[int], Optional[str], Optional[str]]], episodes: List[Tuple[str, str, Optional[str], Optional[str]]]) -> None:
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
            ids = guid_to_ids(guid) if guid else {}
            if not ids:
                ids = simkl_search_ids(headers, show_title, is_movie=False)
                if ids:
                    logger.debug("IDs found in Simkl for show '%s': %s", show_title, ids)
            if not ids:
                logger.warning("Skipping episode '%s - %s' - no IDs found", show_title, code)
                continue
            key = tuple(sorted(ids.items()))
            if key not in shows:
                shows[key] = {"title": show_title, "ids": ids, "seasons": []}
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
                shows[key]["seasons"].append({"number": season_num, "episodes": [{"number": episode_num, "watched_at": watched_at}]})
        if shows:
            payload["shows"] = list(shows.values())

    if not payload:
        logger.info("Nothing new to sync with Simkl")
        return

    logger.info("Adding %d movies and %d shows to Simkl history", len(payload.get("movies", [])), len(payload.get("shows", [])))
    try:
        simkl_request("post", "/sync/history", headers, json=payload)
        logger.info("Simkl history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Simkl: %s", e)


def scrobble_item_to_simkl(headers: dict, item_data: dict, progress: float = 100.0) -> bool:
    """
    Scrobble an item to Simkl using the scrobble endpoint.
    This is used for managed users where we want to mark items as watched.
    
    Args:
        headers: Simkl API headers
        item_data: Dict containing item info (title, year, ids, etc.)
        progress: Progress percentage (default 100.0 to mark as watched)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Use scrobble endpoint with 100% progress to mark as watched
        payload = {
            "progress": progress
        }
        
        if item_data.get("type") == "movie":
            payload["movie"] = {
                "title": item_data.get("title"),
                "year": item_data.get("year"),
                "ids": item_data.get("ids", {})
            }
        elif item_data.get("type") == "episode":
            payload["episode"] = {
                "title": item_data.get("episode_title", ""),
                "season": item_data.get("season"),
                "number": item_data.get("episode"),
                "ids": item_data.get("episode_ids", {})
            }
            if item_data.get("show_ids") or item_data.get("show_title"):
                payload["show"] = {
                    "title": item_data.get("show_title"),
                    "year": item_data.get("show_year"),
                    "ids": item_data.get("show_ids", {})
                }
        
        # Try scrobble/stop endpoint first, fall back to adding to history
        try:
            resp = simkl_request("post", "/scrobble/stop", headers, json=payload)
            if resp.status_code in (200, 201):
                logger.info("Successfully scrobbled %s to Simkl", item_data.get("title", "item"))
                return True
        except Exception:
            # If scrobble fails, try adding directly to history
            pass
        
        # Fallback: Add to watched history directly
        history_payload = {}
        if item_data.get("type") == "movie":
            history_payload["movies"] = [{
                "title": item_data.get("title"),
                "year": item_data.get("year"),
                "ids": item_data.get("ids", {}),
                "watched_at": item_data.get("watched_at")
            }]
        elif item_data.get("type") == "episode":
            show_data = {
                "title": item_data.get("show_title"),
                "ids": item_data.get("show_ids", {}),
                "seasons": [{
                    "number": item_data.get("season"),
                    "episodes": [{
                        "number": item_data.get("episode"),
                        "watched_at": item_data.get("watched_at")
                    }]
                }]
            }
            if item_data.get("show_year"):
                show_data["year"] = item_data.get("show_year")
            history_payload["shows"] = [show_data]
        
        resp = simkl_request("post", "/sync/history", headers, json=history_payload)
        if resp.status_code in (200, 201):
            logger.info("Successfully added %s to Simkl history", item_data.get("title", "item"))
            return True
        else:
            logger.error("Failed to add %s to Simkl: HTTP %d", item_data.get("title", "item"), resp.status_code)
            return False
            
    except Exception as exc:
        logger.error("Error scrobbling %s to Simkl: %s", item_data.get("title", "item"), exc)
        return False


def update_simkl_for_managed_user(headers: dict, movies: list, episodes: list) -> None:
    """
    Update Simkl for a managed user using scrobble/history endpoints.
    This marks items as watched by scrobbling them or adding to history.
    
    Args:
        headers: Simkl API headers  
        movies: List of movie data (title, year, guid, watched_at)
        episodes: List of episode data (show_title, code, guid, watched_at)
    """
    logger.info("Syncing %d movies and %d episodes to Simkl for managed user", 
                len(movies), len(episodes))
    
    synced_movies = 0
    synced_episodes = 0
    
    # Sync movies
    for title, year, guid, watched_at in movies:
        if not guid:
            continue
            
        # Get IDs from GUID
        ids = guid_to_ids(guid)
        
        item_data = {
            "type": "movie",
            "title": title,
            "year": year,
            "ids": ids,
            "watched_at": watched_at
        }
        
        if scrobble_item_to_simkl(headers, item_data):
            synced_movies += 1
    
    # Sync episodes
    for show_title, code, guid, watched_at in episodes:
        if not guid:
            continue
            
        # Parse season/episode from code (format: S01E01)
        try:
            season_match = code.split("S")[1].split("E")[0]
            episode_match = code.split("E")[1]
            season_num = int(season_match)
            episode_num = int(episode_match)
        except (IndexError, ValueError):
            logger.warning("Invalid episode code format: %s", code)
            continue
            
        # For episodes, we need show IDs - try to get them from the library
        show_ids = {}
        try:
            from app import get_plex_server
            from utils import get_show_from_library, imdb_guid, best_guid
            plex_server = get_plex_server()
            if plex_server:
                show_obj = get_show_from_library(plex_server, show_title)
                if show_obj:
                    show_guid = imdb_guid(show_obj) or best_guid(show_obj)
                    if show_guid:
                        show_ids = guid_to_ids(show_guid)
        except Exception as exc:
            logger.debug("Could not get show IDs for %s: %s", show_title, exc)
        
        # Episode IDs from the episode GUID
        episode_ids = guid_to_ids(guid)
        
        item_data = {
            "type": "episode", 
            "show_title": show_title,
            "show_ids": show_ids,
            "season": season_num,
            "episode": episode_num,
            "episode_ids": episode_ids,
            "watched_at": watched_at
        }
        
        if scrobble_item_to_simkl(headers, item_data):
            synced_episodes += 1
    
    logger.info("Successfully synced %d movies and %d episodes to Simkl",
                synced_movies, synced_episodes)


def sync_simkl_ratings(plex, headers):
    """Sync movie and show ratings from Plex to Simkl."""
    from plex_utils import get_cached_ratings

    movies: List[dict] = []
    shows: List[dict] = []

    rated_now = to_iso_z(datetime.utcnow())

    cached_ratings = get_cached_ratings(plex)
    logger.info("Using cached ratings for %d sections", len(cached_ratings))

    for section in plex.library.sections():
        section_key = str(section.key)
        section_ratings = cached_ratings.get(section_key, {})

        if not section_ratings:
            logger.debug("No cached ratings found for section: %s", section.title)
            continue

        logger.debug(
            "Processing %d rated items in section: %s", len(section_ratings), section.title
        )

        if section.type == "movie":
            for rating_key, rating in section_ratings.items():
                try:
                    item = plex.fetchItem(int(rating_key))
                    guid = best_guid(item)
                    obj: Dict[str, Union[str, int, dict]] = {
                        "title": item.title,
                        "rating": int(round(float(rating))),
                        "rated_at": rated_now,
                    }
                    if getattr(item, "year", None):
                        obj["year"] = normalize_year(item.year)
                    if guid:
                        obj["ids"] = guid_to_ids(guid)
                    movies.append(obj)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Failed to fetch movie with rating key %s: %s", rating_key, exc
                    )
                    continue

        elif section.type == "show":
            for rating_key, rating in section_ratings.items():
                try:
                    item = plex.fetchItem(int(rating_key))
                    if item.type != "show":
                        continue  # Simkl does not support rating seasons or episodes
                    guid = best_guid(item)
                    obj: Dict[str, Union[str, int, dict]] = {
                        "title": item.title,
                        "rating": int(round(float(rating))),
                        "rated_at": rated_now,
                    }
                    if getattr(item, "year", None):
                        obj["year"] = normalize_year(item.year)
                    if guid:
                        obj["ids"] = guid_to_ids(guid)
                    shows.append(obj)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Failed to fetch show with rating key %s: %s", rating_key, exc
                    )
                    continue

    payload: Dict[str, list] = {}
    if movies:
        payload["movies"] = movies
    if shows:
        payload["shows"] = shows

    if payload:
        simkl_request("POST", "/sync/ratings", headers, json=payload)
        logger.info(
            "Synced %d movie and %d show ratings to Simkl",
            len(movies),
            len(shows),
        )
    else:
        logger.info("No Plex ratings to sync")


def fetch_simkl_ratings(headers) -> List[dict]:
    """Return all ratings from Simkl."""
    try:
        resp = simkl_request("GET", "/sync/ratings", headers)
        data = resp.json() if resp.content else {}
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch ratings from Simkl: %s", exc)
        return []

    items: List[dict] = []
    for m in data.get("movies", []):
        items.append({"type": "movie", "ids": m.get("ids", {}), "rating": m.get("rating")})
    for s in data.get("shows", []):
        items.append({"type": "show", "ids": s.get("ids", {}), "rating": s.get("rating")})
    return items


def apply_simkl_ratings(plex, headers):
    """Apply ratings from Simkl to matching Plex items."""
    ratings = fetch_simkl_ratings(headers)
    count = 0
    for item in ratings:
        ids = item.get("ids", {})
        rating = item.get("rating")
        if rating is None:
            continue

        guid = None
        if ids.get("imdb"):
            guid = f"imdb://{ids['imdb']}"
        elif ids.get("tmdb"):
            guid = f"tmdb://{ids['tmdb']}"
        elif ids.get("tvdb"):
            guid = f"tvdb://{ids['tvdb']}"
        if not guid:
            continue

        plex_item = find_item_by_guid(plex, guid)
        if not plex_item:
            continue

        try:
            plex_item.rate(float(rating))
            count += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to rate item %s: %s", guid, exc)

    if count:
        logger.info("Applied %d ratings from Simkl to Plex", count)
