import json
import logging
import os
from typing import Dict, List, Optional, Tuple, Union

import requests

from utils import guid_to_ids, normalize_year, simkl_episode_key, to_iso_z

logger = logging.getLogger(__name__)

APP_NAME = "PlexyTrack"
APP_VERSION = "v0.2.7"
USER_AGENT = f"{APP_NAME} / {APP_VERSION}"

SIMKL_TOKEN_FILE = "simkl_tokens.json"


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
    save_simkl_token(data["access_token"])
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


def get_simkl_history(
    headers: dict, *, date_from: Optional[str] = None
) -> Tuple[
    Dict[str, Tuple[str, Optional[int], Optional[str]]],
    Dict[str, Tuple[str, str, Optional[str]]],
]:
    movies: Dict[str, Tuple[str, Optional[int], Optional[str]]] = {}
    episodes: Dict[str, Tuple[str, str, Optional[str]]] = {}

    params = {"type": "movies"}
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
