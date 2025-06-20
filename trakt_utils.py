import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

import requests

from utils import guid_to_ids, normalize_year, to_iso_z, valid_guid, best_guid, imdb_guid, get_show_from_library, ensure_collection, find_item_by_guid

logger = logging.getLogger(__name__)

APP_NAME = "PlexyTrack"
APP_VERSION = "v0.3.0"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"

TOKEN_FILE = "trakt_tokens.json"


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
            json.dump({"access_token": access_token, "refresh_token": refresh_token}, f, indent=2)
        logger.info("Saved Trakt tokens to %s", TOKEN_FILE)
    except Exception as exc:
        logger.error("Failed to save Trakt tokens: %s", exc)




def get_trakt_redirect_uri() -> str:
    global TRAKT_REDIRECT_URI
    if 'TRAKT_REDIRECT_URI' in globals() and TRAKT_REDIRECT_URI:
        return TRAKT_REDIRECT_URI
    TRAKT_REDIRECT_URI = os.environ.get("TRAKT_REDIRECT_URI")
    if TRAKT_REDIRECT_URI:
        return TRAKT_REDIRECT_URI
    try:
        try:
            from flask import has_request_context, request
            if has_request_context():
                TRAKT_REDIRECT_URI = request.url_root.rstrip("/") + "/oauth/trakt"
                return TRAKT_REDIRECT_URI
        except (ImportError, AttributeError):
            pass
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
    save_trakt_tokens(data["access_token"], data.get("refresh_token"))
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
    save_trakt_tokens(data["access_token"], os.environ["TRAKT_REFRESH_TOKEN"])
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
    try:
        trakt_request("POST", "/sync/history", headers, json=payload)
        logger.info("Trakt history updated successfully.")
    except requests.exceptions.RequestException as e:
        logger.error("Failed to update Trakt history: %s", e)


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


def sync_watchlist(plex, headers, plex_history, trakt_history, *, direction="both"):
    # Import here to avoid circular imports
    from app import get_plex_account
    
    account = get_plex_account()
    if account is None:
        try:
            account = plex.myPlexAccount()
        except Exception:  # noqa: BLE001
            account = None
    if account is None:
        logger.error("No Plex account available for watchlist sync")
        return
    
    try:
        plex_watch = account.watchlist()
    except Exception as exc:
        logger.error("Failed to fetch Plex watchlist: %s", exc)
        plex_watch = []
    try:
        trakt_movies = trakt_request("GET", "/sync/watchlist/movies", headers).json()
        trakt_shows = trakt_request("GET", "/sync/watchlist/shows", headers).json()
    except Exception as exc:
        logger.error("Failed to fetch Trakt watchlist: %s", exc)
        return

    plex_guids = set()
    for item in plex_watch:
        g = imdb_guid(item)
        if g:
            plex_guids.add(g)

    trakt_guids = set()
    for lst in (trakt_movies, trakt_shows):
        for it in lst:
            ids = it.get(it["type"], {}).get("ids", {})
            if ids.get("imdb"):
                trakt_guids.add(f"imdb://{ids['imdb']}")
            elif ids.get("tmdb"):
                trakt_guids.add(f"tmdb://{ids['tmdb']}")
            elif ids.get("tvdb"):
                trakt_guids.add(f"tvdb://{ids['tvdb']}")

    movies_to_add = []
    shows_to_add = []
    for item in plex_watch:
        guid = imdb_guid(item)
        if not guid or guid in trakt_guids:
            continue
        data = guid_to_ids(guid)
        if item.TYPE == "movie":
            movies_to_add.append({"ids": data})
        elif item.TYPE == "show":
            shows_to_add.append({"ids": data})
    payload = {}
    if direction in ("both", "plex_to_service"):
        if movies_to_add:
            payload["movies"] = movies_to_add
        if shows_to_add:
            payload["shows"] = shows_to_add
        if payload:
            trakt_request("POST", "/sync/watchlist", headers, json=payload)
            logger.info("Added %d items to Trakt watchlist", len(movies_to_add) + len(shows_to_add))

    add_to_plex = []
    if direction in ("both", "service_to_plex"):
        for lst in (trakt_movies, trakt_shows):
            for it in lst:
                data = it.get(it["type"], {})
                ids = data.get("ids", {})
                guid = None
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                if not guid or guid in plex_guids:
                    continue
                item = find_item_by_guid(plex, guid)
                if item:
                    add_to_plex.append(item)
        if add_to_plex:
            try:
                account.addToWatchlist(add_to_plex)
                logger.info("Added %d items to Plex watchlist", len(add_to_plex))
            except Exception as exc:
                logger.error("Failed adding Plex watchlist items: %s", exc)

    if direction in ("both", "service_to_plex"):
        for guid in list(plex_guids):
            if guid in trakt_history or guid in plex_history:
                try:
                    item = find_item_by_guid(plex, guid)
                    if item:
                        account.removeFromWatchlist([item])
                except Exception:
                    pass
    remove = []
    if direction in ("both", "plex_to_service"):
        for lst in (trakt_movies, trakt_shows):
            for it in lst:
                data = it.get(it["type"], {})
                ids = data.get("ids", {})
                guid = None
                if ids.get("imdb"):
                    guid = f"imdb://{ids['imdb']}"
                elif ids.get("tmdb"):
                    guid = f"tmdb://{ids['tmdb']}"
                elif ids.get("tvdb"):
                    guid = f"tvdb://{ids['tvdb']}"
                if guid and (guid in plex_history or guid in trakt_history) and guid not in plex_guids:
                    remove.append({"ids": guid_to_ids(guid)})
        if remove:
            trakt_request("POST", "/sync/watchlist/remove", headers, json={"movies": remove, "shows": remove})
            logger.info("Removed %d items from Trakt watchlist", len(remove))


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
