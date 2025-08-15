import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

import requests

from plexapi.myplex import MyPlexAccount

# Plex switched watchlist-related endpoints to the Discover domain.
# Ensure PlexAPI uses the new base URL when this module is imported
# independently of ``app.py``.
MyPlexAccount.METADATA = MyPlexAccount.DISCOVER

from utils import (
    guid_to_ids,
    normalize_year,
    to_iso_z,
    valid_guid,
    best_guid,
    imdb_guid,
    get_show_from_library,
    ensure_collection,
    find_item_by_guid,
)

logger = logging.getLogger(__name__)

APP_NAME = "PlexyTrack"
APP_VERSION = "v0.4.3"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"
CONFIG_DIR = os.environ.get("PLEXYTRACK_CONFIG_DIR", "/config")
STATE_DIR = os.environ.get("PLEXYTRACK_STATE_DIR", "/state")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.json")
WATCHLIST_STATE_FILE = os.path.join(STATE_DIR, "watchlist_state.json")


def load_watchlist_state() -> dict:
    """Return the cached watchlist state if available."""
    # Ensure state directory exists
    os.makedirs(os.path.dirname(WATCHLIST_STATE_FILE), exist_ok=True)
    
    if os.path.exists(WATCHLIST_STATE_FILE):
        try:
            with open(WATCHLIST_STATE_FILE, "r", encoding="utf-8") as f:
                logger.debug("Loading watchlist state from %s", WATCHLIST_STATE_FILE)
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load watchlist state: %s", exc)
    else:
        logger.debug("No existing watchlist state file found at %s", WATCHLIST_STATE_FILE)
    return {
        "plex": {"guids": [], "types": {}, "meta": {}, "last_sync": None},
        "trakt": {"movies": [], "shows": [], "last_activity": None, "last_sync": None},
    }


def save_watchlist_state(state: dict) -> None:
    """Persist watchlist ``state`` to disk."""
    try:
        # Ensure state directory exists
        os.makedirs(os.path.dirname(WATCHLIST_STATE_FILE), exist_ok=True)
        with open(WATCHLIST_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        logger.debug("Saved watchlist state to %s", WATCHLIST_STATE_FILE)
    except Exception as exc:
        logger.warning("Failed to save watchlist state: %s", exc)


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


def save_trakt_tokens(access_token: str, refresh_token: Optional[str], expires_in: Optional[int] = None) -> None:
    auth = load_auth()
    auth["trakt"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": int(time.time()) + int(expires_in) if expires_in else None,
    }
    save_auth(auth)
    logger.info("Saved Trakt tokens to %s", AUTH_FILE)




def get_trakt_redirect_uri() -> str:
    """Return the Trakt redirect URI for the current request."""
    uri = os.environ.get("TRAKT_REDIRECT_URI")
    if uri:
        return uri
    try:
        from flask import has_request_context, request
        if has_request_context():
            return request.url_root.rstrip("/") + "/oauth/trakt"
    except Exception:
        pass
    return "http://localhost:5030/oauth/trakt"


def exchange_code_for_tokens(code: str, redirect_uri: Optional[str] = None) -> Optional[dict]:
    if redirect_uri is None:
        redirect_uri = get_trakt_redirect_uri()
    client_id = os.environ.get("TRAKT_CLIENT_ID")
    client_secret = os.environ.get("TRAKT_CLIENT_SECRET")
    if not all([code, client_id, client_secret]):
        logger.error("Missing code or Trakt client credentials.")
        return None

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    try:
        resp = requests.post("https://api.trakt.tv/oauth/token", json=payload, timeout=30)
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


def refresh_trakt_token(redirect_uri: str) -> Optional[str]:
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
        "redirect_uri": redirect_uri,
        "grant_type": "refresh_token",
    }
    try:
        resp = requests.post("https://api.trakt.tv/oauth/token", json=payload, timeout=30)
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


def trakt_request(method: str, endpoint: str, headers: dict, **kwargs) -> requests.Response:
    url = f"https://api.trakt.tv{endpoint}"

    headers.setdefault("User-Agent", USER_AGENT)

    resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
    if resp.status_code == 401:
        new_token = refresh_trakt_token(headers.get("redirect_uri", ""))
        if new_token:
            headers["Authorization"] = f"Bearer {new_token}"
            resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

    if resp.status_code == 420:
        msg = (
            "Trakt API returned 420 – account limit exceeded. "
            "Upgrade to VIP or reduce the size of your collection/watchlist."
        )
        logger.warning(msg)
        raise Exception(msg)

    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "1"))
        logger.warning("Trakt API rate limit reached. Retrying in %s seconds", retry_after)
        time.sleep(retry_after)
        resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)

    resp.raise_for_status()
    return resp


def get_trakt_history(
    headers: dict,
    *,
    date_from: Optional[str] = None,
) -> Tuple[
    Dict[str, Tuple[str, Optional[int], Optional[str]]],
    Dict[str, Tuple[str, str, Optional[str]]],
]:
    movies: Dict[str, Tuple[str, Optional[int], Optional[str]]] = {}
    episodes: Dict[str, Tuple[str, str, Optional[str]]] = {}

    page = 1
    logger.info("Fetching Trakt history…")
    params = {"page": page, "limit": 100}
    if date_from:
        params["start_at"] = date_from
    while True:
        params["page"] = page
        resp = trakt_request("GET", "/sync/history", headers, params=params)
        data = resp.json()
        if not isinstance(data, list) or not data:
            break
        for item in data:
            watched_at = item.get("watched_at")
            if item["type"] == "movie":
                m = item["movie"]
                ids = m.get("ids", {})
                guid = None
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                if guid and guid not in movies:
                    movies[guid] = (m["title"], normalize_year(m.get("year")), watched_at)
            elif item["type"] == "episode":
                e = item["episode"]
                show = item["show"]
                ids = e.get("ids", {})
                guid = None
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                if guid and guid not in episodes:
                    episodes[guid] = (show["title"], f"S{e['season']:02d}E{e['number']:02d}", watched_at)
        page += 1

    return movies, episodes


def update_trakt(headers: dict, movies: list, episodes: list) -> None:
    """Add new items to Trakt history with fallback ID search when GUIDs are not available."""
    payload = {"movies": [], "episodes": []}

    # Movies: Try GUID first, then fallback to search if needed
    for title, year, watched_at, guid in movies:
        ids = None
        
        # Try to get IDs from GUID first
        if guid and isinstance(guid, str) and valid_guid(guid):
            ids = guid_to_ids(guid)
            
        # Fallback: search Trakt by title if no valid GUID
        if not ids:
            ids = trakt_search_ids(headers, title, is_movie=True, year=year)
            if ids:
                logger.debug("IDs found in Trakt search for movie '%s': %s", title, ids)
        
        if ids:
            item = {"title": title, "ids": ids}
            if year is not None:
                item["year"] = year
            if watched_at:
                item["watched_at"] = watched_at
            payload["movies"].append(item)
            logger.debug("Added movie '%s' to Trakt payload", title)
        else:
            logger.warning("Skipping movie '%s' (%s) - no IDs found", title, year)

    # Episodes: Use flexible approach - individual episode IDs if available, otherwise group by show
    episodes_added_individually = set()
    shows = {}
    
    for show_title, code, watched_at, guid in episodes:
        # Extract season and episode numbers from code (format: S01E01)
        try:
            season = int(code[1:3])
            number = int(code[4:6])
        except (ValueError, IndexError):
            logger.warning("Invalid episode code format: %s", code)
            continue
        
        # Try individual episode approach first (if we have a valid episode GUID)
        if guid and isinstance(guid, str) and valid_guid(guid):
            episode_ids = guid_to_ids(guid)
            if episode_ids:
                episode_obj = {
                    "season": season,
                    "number": number,
                    "ids": episode_ids
                }
                if watched_at:
                    episode_obj["watched_at"] = watched_at
                payload["episodes"].append(episode_obj)
                episodes_added_individually.add((show_title, code))
                logger.debug("Added individual episode '%s - %s' (S%02dE%02d) with episode GUID '%s' to Trakt payload", show_title, code, season, number, guid)
                continue
        
        # Fallback: Group episodes by show (using show GUID or search)
        show_ids = None
        
        # Try to get show IDs from episode GUID first (might be a show GUID)
        if guid and isinstance(guid, str) and valid_guid(guid):
            show_ids = guid_to_ids(guid)
        
        # If no IDs from GUID, try searching Trakt by show title
        if not show_ids:
            show_ids = trakt_search_ids(headers, show_title, is_movie=False)
            if show_ids:
                logger.debug("IDs found in Trakt search for show '%s': %s", show_title, show_ids)
        
        if show_ids:
            # Group episodes by show
            key = tuple(sorted(show_ids.items()))
            if key not in shows:
                shows[key] = {
                    "title": show_title,
                    "ids": show_ids,
                    "seasons": []
                }
            
            # Add episode to the appropriate season
            season_found = False
            for s in shows[key]["seasons"]:
                if s["number"] == season:
                    s["episodes"].append({"number": number, "watched_at": watched_at})
                    season_found = True
                    break
            
            if not season_found:
                shows[key]["seasons"].append({
                    "number": season,
                    "episodes": [{"number": number, "watched_at": watched_at}]
                })
            
            logger.debug("Added episode '%s - %s' (S%02dE%02d) to show group in Trakt payload", show_title, code, season, number)
        else:
            logger.warning("Skipping episode '%s - %s' - no IDs found (no episode GUID or show lookup failed)", show_title, code)
    
    # Add grouped show episodes to payload
    if shows:
        if "shows" not in payload:
            payload["shows"] = []
        payload["shows"].extend(list(shows.values()))

    if not payload["movies"] and not payload["episodes"] and not payload.get("shows"):
        logger.info("Nothing new to send to Trakt.")
        return

    logger.info(
        "Adding %d movies, %d individual episodes, and %d shows (with episodes) to Trakt history",
        len(payload["movies"]),
        len(payload["episodes"]),
        len(payload.get("shows", [])),
    )

    def chunk_list(items: List[dict], size: int = 500) -> List[List[dict]]:
        """Split ``items`` into chunks of ``size`` items."""
        return [items[i : i + size] for i in range(0, len(items), size)]

    movie_chunks = chunk_list(payload["movies"])
    episode_chunks = chunk_list(payload["episodes"])
    show_chunks = chunk_list(payload.get("shows", []))

    max_batches = max(len(movie_chunks), len(episode_chunks), len(show_chunks))

    for batch_num in range(max_batches):
        batch_payload = {}
        if batch_num < len(movie_chunks):
            batch_payload["movies"] = movie_chunks[batch_num]
        if batch_num < len(episode_chunks):
            batch_payload["episodes"] = episode_chunks[batch_num]
        if batch_num < len(show_chunks):
            batch_payload["shows"] = show_chunks[batch_num]

        # Retry up to 3 times for rate limit responses
        retries = 3
        while retries:
            try:
                trakt_request("POST", "/sync/history", headers, json=batch_payload)
                logger.debug(
                    "Sent Trakt history batch %d with %d movies, %d episodes, %d shows",
                    batch_num + 1,
                    len(batch_payload.get("movies", [])),
                    len(batch_payload.get("episodes", [])),
                    len(batch_payload.get("shows", [])),
                )
                break
            except requests.exceptions.HTTPError as exc:
                if (
                    exc.response is not None
                    and exc.response.status_code == 429
                    and retries > 1
                ):
                    retry_after = int(exc.response.headers.get("Retry-After", "1"))
                    logger.warning(
                        "Trakt API rate limit reached. Retrying batch in %s seconds",
                        retry_after,
                    )
                    time.sleep(retry_after)
                    retries -= 1
                    continue
                raise
            except requests.exceptions.RequestException as exc:
                logger.error(
                    "Failed to update Trakt history batch %d: %s", batch_num + 1, exc
                )
                raise

    logger.info("Trakt history updated successfully.")


def sync_collection(plex, headers):
    movies = []
    for section in plex.library.sections():
        if section.type == "movie":
            for item in section.all():
                guid = best_guid(item)
                obj = {"title": item.title}
                if getattr(item, "year", None):
                    obj["year"] = normalize_year(item.year)
                if guid:
                    obj["ids"] = guid_to_ids(guid)
                movies.append(obj)
    if movies:
        trakt_request("POST", "/sync/collection", headers, json={"movies": movies})
        logger.info("Synced %d Plex movies to Trakt collection", len(movies))


def sync_ratings(plex, headers):
    """Sync ratings from Plex to Trakt using cached ratings for better performance."""
    from plex_utils import get_cached_ratings
    
    movies: List[dict] = []
    shows: List[dict] = []
    episodes: List[dict] = []

    rated_now = to_iso_z(datetime.utcnow())
    
    # Get cached ratings for better performance
    cached_ratings = get_cached_ratings(plex)
    logger.info("Using cached ratings for %d sections", len(cached_ratings))

    for section in plex.library.sections():
        section_key = str(section.key)
        section_ratings = cached_ratings.get(section_key, {})
        
        if not section_ratings:
            logger.debug("No cached ratings found for section: %s", section.title)
            continue
            
        logger.debug("Processing %d rated items in section: %s", len(section_ratings), section.title)
        
        if section.type == "movie":
            # Use cache to only fetch items that have ratings
            for rating_key, rating in section_ratings.items():
                try:
                    item = plex.fetchItem(int(rating_key))
                    guid = best_guid(item)
                    obj = {
                        "title": item.title,
                        "rating": int(round(float(rating))),
                        "rated_at": rated_now,
                    }
                    if getattr(item, "year", None):
                        obj["year"] = normalize_year(item.year)
                    if guid:
                        obj["ids"] = guid_to_ids(guid)
                    movies.append(obj)
                except Exception as exc:
                    logger.debug("Failed to fetch movie with rating key %s: %s", rating_key, exc)
                    continue
                    
        elif section.type == "show":
            # For shows, we need to determine if rating belongs to show, season, or episode
            for rating_key, rating in section_ratings.items():
                try:
                    item = plex.fetchItem(int(rating_key))
                    
                    if item.type == "show":
                        # Show rating
                        show_guid = best_guid(item)
                        show_ids = guid_to_ids(show_guid) if show_guid else {}
                        base = {"title": item.title}
                        if getattr(item, "year", None):
                            base["year"] = normalize_year(item.year)
                        if show_ids:
                            base["ids"] = show_ids
                        base["rating"] = int(round(float(rating)))
                        base["rated_at"] = rated_now
                        shows.append(base)
                        
                    elif item.type == "season":
                        # Season rating - add to parent show
                        show = item.show()
                        show_guid = best_guid(show)
                        show_ids = guid_to_ids(show_guid) if show_guid else {}
                        base = {"title": show.title}
                        if getattr(show, "year", None):
                            base["year"] = normalize_year(show.year)
                        if show_ids:
                            base["ids"] = show_ids
                        base["seasons"] = [{
                            "number": int(item.index), 
                            "rating": int(round(float(rating))), 
                            "rated_at": rated_now
                        }]
                        shows.append(base)
                        
                    elif item.type == "episode":
                        # Episode rating
                        season = item.season()
                        show = season.show()
                        ep_obj = {
                            "season": int(season.index), 
                            "number": int(item.index), 
                            "rating": int(round(float(rating))), 
                            "rated_at": rated_now
                        }
                        ep_guid = best_guid(item)
                        if ep_guid:
                            ep_obj["ids"] = guid_to_ids(ep_guid)
                        elif show:
                            show_guid = best_guid(show)
                            show_ids = guid_to_ids(show_guid) if show_guid else {}
                            if show_ids:
                                ep_obj["show"] = {"ids": show_ids}
                            else:
                                ep_obj["title"] = show.title
                        episodes.append(ep_obj)
                        
                except Exception as exc:
                    logger.debug("Failed to fetch item with rating key %s: %s", rating_key, exc)
                    continue

    payload = {}
    if movies:
        payload["movies"] = movies
    if shows:
        payload["shows"] = shows
    if episodes:
        payload["episodes"] = episodes

    if payload:
        trakt_request("POST", "/sync/ratings", headers, json=payload)
        logger.info(
            "Synced %d movie ratings, %d shows and %d episode ratings to Trakt",
            len(movies),
            len(shows),
            len(episodes),
        )
    else:
        logger.info("No Plex ratings to sync")


def apply_trakt_ratings(plex, headers):
    """Apply ratings from Trakt to matching Plex items."""
    ratings = fetch_trakt_ratings(headers)
    count = 0
    for item in ratings:
        typ = item.get("type")
        data = item.get(typ, {}) if typ else {}
        ids = data.get("ids", {})
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
        except Exception as exc:
            logger.debug("Failed to rate item %s: %s", guid, exc)
    if count:
        logger.info("Applied %d ratings from Trakt to Plex", count)


def sync_liked_lists(plex, headers):
    try:
        likes = trakt_request("GET", "/users/likes/lists", headers).json()
    except Exception as exc:
        logger.error("Failed to fetch liked lists: %s", exc)
        return
    for like in likes:
        lst = like.get("list", {})
        owner = lst.get("user", {}).get("ids", {}).get("slug") or lst.get("user", {}).get("username")
        slug = lst.get("ids", {}).get("slug")
        name = lst.get("name", slug)
        if not owner or not slug:
            continue
        try:
            items = trakt_request("GET", f"/users/{owner}/lists/{slug}/items", headers).json()
        except Exception as exc:
            logger.error("Failed to fetch list %s/%s: %s", owner, slug, exc)
            continue
        movie_items = []
        show_items = []
        for it in items:
            data = it.get(it["type"], {})
            ids = data.get("ids", {})
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
            if plex_item:
                if plex_item.TYPE == "movie":
                    movie_items.append(plex_item)
                elif plex_item.TYPE == "show":
                    show_items.append(plex_item)
        if movie_items or show_items:
            for sec in plex.library.sections():
                if sec.type == "movie" and movie_items:
                    coll = ensure_collection(plex, sec, name, first_item=movie_items[0])
                    try:
                        if len(movie_items) > 1:
                            coll.addItems(movie_items[1:])
                    except Exception:
                        pass
                if sec.type == "show" and show_items:
                    coll = ensure_collection(plex, sec, name, first_item=show_items[0])
                    try:
                        if len(show_items) > 1:
                            coll.addItems(show_items[1:])
                    except Exception:
                        pass


def sync_collections_to_trakt(plex, headers):
    try:
        user_data = trakt_request("GET", "/users/settings", headers).json()
        username = user_data.get("user", {}).get("ids", {}).get("slug") or user_data.get("user", {}).get("username")
        lists = trakt_request("GET", f"/users/{username}/lists", headers).json()
    except Exception as exc:
        logger.error("Failed to fetch Trakt lists: %s", exc)
        return

    slug_by_name = {l.get("name"): l.get("ids", {}).get("slug") for l in lists}

    for sec in plex.library.sections():
        if sec.type not in ("movie", "show"):
            continue
        for coll in sec.collections():
            slug = slug_by_name.get(coll.title)
            if not slug:
                try:
                    resp = trakt_request("POST", f"/users/{username}/lists", headers, json={"name": coll.title})
                    slug = resp.json().get("ids", {}).get("slug")
                    slug_by_name[coll.title] = slug
                except Exception as exc:
                    logger.error("Failed creating list %s: %s", coll.title, exc)
                    continue
            try:
                items = trakt_request("GET", f"/users/{username}/lists/{slug}/items", headers).json()
            except Exception as exc:
                logger.error("Failed to fetch list %s items: %s", slug, exc)
                continue
            trakt_guids = set()
            for it in items:
                data = it.get(it["type"], {})
                ids = data.get("ids", {})
                if ids.get("imdb"):
                    trakt_guids.add(f"imdb://{ids['imdb']}")
                elif ids.get("tmdb"):
                    trakt_guids.add(f"tmdb://{ids['tmdb']}")
                elif ids.get("tvdb"):
                    trakt_guids.add(f"tvdb://{ids['tvdb']}")
            movies = []
            shows = []
            for item in coll.items():
                guid = imdb_guid(item)
                if not guid or guid in trakt_guids:
                    continue
                if item.type == "movie":
                    movies.append({"ids": guid_to_ids(guid)})
                elif item.type == "show":
                    shows.append({"ids": guid_to_ids(guid)})
            payload = {}
            if movies:
                payload["movies"] = movies
            if shows:
                payload["shows"] = shows
            if payload:
                try:
                    trakt_request("POST", f"/users/{username}/lists/{slug}/items", headers, json=payload)
                    logger.info("Updated Trakt list %s with %d items", slug, len(movies) + len(shows))
                except Exception as exc:
                    logger.error("Failed updating list %s: %s", slug, exc)


def sync_watchlist(
    plex,
    headers,
    plex_history=None,
    trakt_history=None,
    *,
    direction="both",
):
    """Synchronize Plex and Trakt watchlists with 'Last Action Wins' behavior.

    This implementation tracks changes since the last sync and applies them
    unidirectionally to respect user intentions and prevent infinite re-additions.
    """
    from datetime import datetime
    from app import WATCHLIST_CONFLICT_RESOLUTION, WATCHLIST_REMOVAL_ENABLED
    
    logger.info("Starting watchlist sync (direction: %s, resolution: %s)", 
                direction, WATCHLIST_CONFLICT_RESOLUTION)

    plex_history = plex_history or set()
    trakt_history = trakt_history or set()

    # Import here to avoid circular imports
    from app import get_plex_account

    logger.debug("Loading watchlist state...")
    state = load_watchlist_state()

    logger.debug("Getting Plex account...")
    account = get_plex_account()
    if account is None:
        try:
            logger.debug("Attempting to get account from plex server...")
            account = plex.myPlexAccount()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to get Plex account from server: %s", exc)
            account = None
    if account is None:
        logger.error("No Plex account available for watchlist sync")
        return

    current_time = datetime.utcnow().isoformat() + "Z"
    
    # Get current watchlists from both platforms
    logger.info("Fetching current watchlists from both platforms...")
    
    # Fetch current Trakt watchlist
    try:
        trakt_movies = trakt_request("GET", "/sync/watchlist/movies", headers).json()
        trakt_shows = trakt_request("GET", "/sync/watchlist/shows", headers).json()
        logger.debug("Fetched %d movies and %d shows from Trakt watchlist", 
                    len(trakt_movies), len(trakt_shows))
    except Exception as exc:
        logger.error("Failed to fetch Trakt watchlist: %s", exc)
        return
        
    current_trakt_guids = set()
    for it in trakt_movies:
        ids = it.get("movie", {}).get("ids", {})
        if ids.get("imdb"):
            current_trakt_guids.add(f"imdb://{ids['imdb']}")
        elif ids.get("tmdb"):
            current_trakt_guids.add(f"tmdb://{ids['tmdb']}")
        elif ids.get("tvdb"):
            current_trakt_guids.add(f"tvdb://{ids['tvdb']}")
    for it in trakt_shows:
        ids = it.get("show", {}).get("ids", {})
        if ids.get("imdb"):
            current_trakt_guids.add(f"imdb://{ids['imdb']}")
        elif ids.get("tmdb"):
            current_trakt_guids.add(f"tmdb://{ids['tmdb']}")
        elif ids.get("tvdb"):
            current_trakt_guids.add(f"tvdb://{ids['tvdb']}")

    # Fetch current Plex watchlist
    try:
        plex_watch = account.watchlist()
        logger.debug("Fetched %d items from Plex watchlist", len(plex_watch))
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch Plex watchlist: %s", exc)
        plex_watch = []
        
    current_plex_guids = set()
    current_plex_types = {}
    for item in plex_watch:
        g = imdb_guid(item)
        if g:
            current_plex_guids.add(g)
            current_plex_types[g] = item.TYPE

    # Get previous state
    previous_trakt_guids = set(state.get("trakt", {}).get("movies", []) + state.get("trakt", {}).get("shows", []))
    previous_plex_guids = set(state.get("plex", {}).get("guids", []))
    previous_plex_types = state.get("plex", {}).get("types", {})
    
    logger.info("Watchlist comparison:")
    logger.info("  Previous: %d Plex, %d Trakt", len(previous_plex_guids), len(previous_trakt_guids))
    logger.info("  Current:  %d Plex, %d Trakt", len(current_plex_guids), len(current_trakt_guids))

    # Detect changes since last sync
    plex_added = current_plex_guids - previous_plex_guids
    plex_removed = previous_plex_guids - current_plex_guids
    trakt_added = current_trakt_guids - previous_trakt_guids
    trakt_removed = previous_trakt_guids - current_trakt_guids

    logger.info("Detected changes since last sync:")
    logger.info("  Plex: +%d added, -%d removed", len(plex_added), len(plex_removed))
    logger.info("  Trakt: +%d added, -%d removed", len(trakt_added), len(trakt_removed))

    if WATCHLIST_CONFLICT_RESOLUTION == "additive_only":
        logger.info("Using additive-only mode: only additions will be synced")
        plex_removed = set()
        trakt_removed = set()
    elif WATCHLIST_CONFLICT_RESOLUTION == "last_wins":
        logger.info("Using last-action-wins mode: changes will be applied bidirectionally")
    
    changes_made = False

    # Apply Plex changes to Trakt
    if direction in ("both", "plex_to_service"):
        # Add items that were added to Plex
        if plex_added:
            logger.info("Applying %d Plex additions to Trakt", len(plex_added))
            movies_to_add = []
            shows_to_add = []
            for guid in plex_added:
                item_type = current_plex_types.get(guid)
                if not item_type:
                    # Try to determine type from Plex item
                    item = find_item_by_guid(plex, guid)
                    if item:
                        item_type = getattr(item, "TYPE", None)
                        current_plex_types[guid] = item_type
                
                data = guid_to_ids(guid)
                if item_type == "movie":
                    movies_to_add.append({"ids": data})
                elif item_type == "show":
                    shows_to_add.append({"ids": data})
            
            if movies_to_add or shows_to_add:
                payload = {}
                if movies_to_add:
                    payload["movies"] = movies_to_add
                if shows_to_add:
                    payload["shows"] = shows_to_add
                try:
                    trakt_request("POST", "/sync/watchlist", headers, json=payload)
                    logger.info("Successfully added %d items to Trakt watchlist", 
                               len(movies_to_add) + len(shows_to_add))
                    changes_made = True
                except Exception as exc:
                    logger.error("Failed to add items to Trakt watchlist: %s", exc)

        # Remove items that were removed from Plex
        if plex_removed and WATCHLIST_REMOVAL_ENABLED:
            logger.info("Applying %d Plex removals to Trakt", len(plex_removed))
            movies_to_remove = []
            shows_to_remove = []
            for guid in plex_removed:
                data = guid_to_ids(guid)
                item_type = previous_plex_types.get(guid)
                if item_type == "movie":
                    movies_to_remove.append({"ids": data})
                elif item_type == "show":
                    shows_to_remove.append({"ids": data})
                else:
                    # Best guess based on current Trakt data
                    if guid in current_trakt_guids:
                        movies_to_remove.append({"ids": data})
                        
            if movies_to_remove or shows_to_remove:
                payload = {}
                if movies_to_remove:
                    payload["movies"] = movies_to_remove
                if shows_to_remove:
                    payload["shows"] = shows_to_remove
                try:
                    trakt_request("POST", "/sync/watchlist/remove", headers, json=payload)
                    logger.info("Successfully removed %d items from Trakt watchlist", 
                               len(movies_to_remove) + len(shows_to_remove))
                    changes_made = True
                except Exception as exc:
                    logger.error("Failed to remove items from Trakt watchlist: %s", exc)

    # Apply Trakt changes to Plex
    if direction in ("both", "service_to_plex"):
        # Add items that were added to Trakt
        if trakt_added:
            logger.info("Applying %d Trakt additions to Plex", len(trakt_added))
            add_to_plex = []
            items_not_found = []
            for guid in trakt_added:
                logger.debug("Looking for Trakt item %s in Plex library", guid)
                item = find_item_by_guid(plex, guid)
                if item:
                    add_to_plex.append(item)
                    current_plex_types[guid] = item.TYPE
                    logger.debug("Found item: %s", getattr(item, 'title', guid))
                else:
                    items_not_found.append(guid)
                    logger.debug("Item not found in Plex library: %s", guid)
            
            if items_not_found:
                logger.info("%d items from Trakt not found in Plex library", len(items_not_found))
                
            if add_to_plex:
                try:
                    account.addToWatchlist(add_to_plex)
                    logger.info("Successfully added %d items to Plex watchlist", len(add_to_plex))
                    changes_made = True
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed adding Plex watchlist items: %s", exc)

        # Remove items that were removed from Trakt
        if trakt_removed and WATCHLIST_REMOVAL_ENABLED:
            logger.info("Applying %d Trakt removals to Plex", len(trakt_removed))
            removed_count = 0
            for guid in trakt_removed:
                try:
                    logger.debug("Looking for item %s to remove from Plex", guid)
                    item = find_item_by_guid(plex, guid)
                    if item:
                        logger.debug("Removing item '%s' from Plex watchlist", getattr(item, 'title', guid))
                        account.removeFromWatchlist([item])
                        removed_count += 1
                        changes_made = True
                    else:
                        logger.debug("Item %s not found in Plex library for removal", guid)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Failed to remove item %s from Plex watchlist: %s", guid, exc)
            
            if removed_count > 0:
                logger.info("Successfully removed %d items from Plex watchlist", removed_count)

    # Update state with current data
    logger.debug("Saving updated watchlist state...")
    try:
        # Recalculate current state after changes
        if changes_made:
            # Re-fetch current state if we made changes
            try:
                plex_watch = account.watchlist()
                current_plex_guids = set()
                current_plex_types = {}
                for item in plex_watch:
                    g = imdb_guid(item)
                    if g:
                        current_plex_guids.add(g)
                        current_plex_types[g] = item.TYPE
                        
                trakt_movies = trakt_request("GET", "/sync/watchlist/movies", headers).json()
                trakt_shows = trakt_request("GET", "/sync/watchlist/shows", headers).json()
                current_trakt_movies = []
                current_trakt_shows = []
                for it in trakt_movies:
                    ids = it.get("movie", {}).get("ids", {})
                    if ids.get("imdb"):
                        current_trakt_movies.append(f"imdb://{ids['imdb']}")
                    elif ids.get("tmdb"):
                        current_trakt_movies.append(f"tmdb://{ids['tmdb']}")
                    elif ids.get("tvdb"):
                        current_trakt_movies.append(f"tvdb://{ids['tvdb']}")
                for it in trakt_shows:
                    ids = it.get("show", {}).get("ids", {})
                    if ids.get("imdb"):
                        current_trakt_shows.append(f"imdb://{ids['imdb']}")
                    elif ids.get("tmdb"):
                        current_trakt_shows.append(f"tmdb://{ids['tmdb']}")
                    elif ids.get("tvdb"):
                        current_trakt_shows.append(f"tvdb://{ids['tvdb']}")
            except Exception as exc:
                logger.warning("Failed to re-fetch watchlists after changes: %s", exc)
        else:
            # Use the data we already fetched
            current_trakt_movies = [g for g in current_trakt_guids if previous_plex_types.get(g) == "movie"]
            current_trakt_shows = [g for g in current_trakt_guids if previous_plex_types.get(g) == "show"]
            # Fill in missing types
            for g in current_trakt_guids:
                if g not in current_trakt_movies and g not in current_trakt_shows:
                    current_trakt_movies.append(g)  # Default to movie if unknown

        # Get Plex watchlist metadata
        total_size = len(current_plex_guids)
        latest_added_at = current_time  # Use current time as proxy
        
        state["plex"] = {
            "guids": list(current_plex_guids),
            "types": current_plex_types,
            "meta": {"size": total_size, "updated_at": latest_added_at},
            "last_sync": current_time,
        }
        state["trakt"] = {
            "movies": current_trakt_movies,
            "shows": current_trakt_shows,
            "last_activity": current_time,
            "last_sync": current_time,
        }
        save_watchlist_state(state)
        logger.debug("Watchlist state saved successfully")
    except Exception as exc:
        logger.error("Failed to save watchlist state: %s", exc)
    
    logger.info("Watchlist sync completed successfully (changes made: %s)", changes_made)


def fetch_trakt_history_full(headers) -> list:
    all_items = []
    page = 1
    while True:
        resp = trakt_request("GET", "/sync/history", headers, params={"page": page, "limit": 100})
        data = resp.json()
        if not data:
            break
        all_items.extend(data)
        page += 1
    return all_items


def fetch_trakt_ratings(headers) -> list:
    all_items = []
    page = 1
    while True:
        resp = trakt_request("GET", "/sync/ratings", headers, params={"page": page, "limit": 100})
        data = resp.json()
        if not data:
            break
        all_items.extend(data)
        page += 1
    return all_items


def fetch_trakt_watchlist(headers) -> dict:
    movies = trakt_request("GET", "/sync/watchlist/movies", headers).json()
    shows = trakt_request("GET", "/sync/watchlist/shows", headers).json()
    return {"movies": movies, "shows": shows}


def restore_backup(headers, data: dict) -> None:
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
                obj = {"ids": ids, "season": ep.get("season"), "number": ep.get("number")}
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


def trakt_search_ids(
    headers: dict,
    title: str,
    *,
    is_movie: bool = True,
    year: Optional[int] = None,
) -> Dict[str, Union[str, int]]:
    """Search for a movie/show on Trakt and return its IDs."""
    media_type = "movie" if is_movie else "show"
    query_params = {"query": title, "type": media_type}
    if year:
        query_params["year"] = year

    resp = trakt_request("GET", "/search", headers, params=query_params)
    data = resp.json()

    for result in data:
        item = result.get(media_type)
        if item:
            ids = item.get("ids", {})
            if ids:
                return ids
    return {}


def scrobble_item_to_trakt(headers: dict, item_data: dict, progress: float = 100.0) -> bool:
    """
    Scrobble an item to Trakt using the /scrobble/stop endpoint.
    This is used for managed users where we want to mark items as watched.
    
    Args:
        headers: Trakt API headers
        item_data: Dict containing item info (title, year, ids, etc.)
        progress: Progress percentage (default 100.0 to mark as watched)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Use scrobble/stop endpoint with 100% progress to mark as watched
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
            if item_data.get("show_ids"):
                payload["show"] = {
                    "title": item_data.get("show_title"),
                    "year": item_data.get("show_year"),
                    "ids": item_data.get("show_ids", {})
                }
        
        resp = trakt_request("POST", "/scrobble/stop", headers, json=payload)
        
        if resp.status_code in (200, 201):
            logger.info("Successfully scrobbled %s to Trakt", item_data.get("title", "item"))
            return True
        elif resp.status_code == 409:
            # Item was already scrobbled recently
            logger.debug("Item already scrobbled recently: %s", item_data.get("title", "item"))
            return True
        else:
            logger.error("Failed to scrobble %s: HTTP %d", item_data.get("title", "item"), resp.status_code)
            return False
            
    except Exception as exc:
        logger.error("Error scrobbling %s to Trakt: %s", item_data.get("title", "item"), exc)
        return False


def update_trakt_for_managed_user(headers: dict, movies: list, episodes: list) -> None:
    """
    Update Trakt for a managed user using scrobble endpoints.
    This marks items as watched by scrobbling them with 100% progress.
    
    Args:
        headers: Trakt API headers  
        movies: List of movie data
        episodes: List of episode data
    """
    logger.info("Syncing %d movies and %d episodes to Trakt for managed user using scrobble", 
                len(movies), len(episodes))
    
    scrobbled_movies = 0
    scrobbled_episodes = 0
    
    # Scrobble movies
    for title, year, watched_at, guid in movies:
        if not guid or not valid_guid(guid):
            continue
            
        # Get IDs from GUID
        ids = guid_to_ids(guid)
        if not ids:
            continue
            
        item_data = {
            "type": "movie",
            "title": title,
            "year": year,
            "ids": ids,
            "watched_at": watched_at
        }
        
        if scrobble_item_to_trakt(headers, item_data):
            scrobbled_movies += 1
    
    # Scrobble episodes
    for show_title, code, watched_at, guid in episodes:
        if not guid or not valid_guid(guid):
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
        
        if scrobble_item_to_trakt(headers, item_data):
            scrobbled_episodes += 1
    
    logger.info("Successfully scrobbled %d movies and %d episodes to Trakt", 
                scrobbled_movies, scrobbled_episodes)
