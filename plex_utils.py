import logging
import os
import json
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

from utils import (
    _parse_guid_value,
    get_show_from_library,
    imdb_guid,
    normalize_year,
    to_iso_z,
    valid_guid,
    find_item_by_guid,
    safe_timestamp_compare,
)

logger = logging.getLogger(__name__)

# Global cache for movie GUIDs to avoid repeated lookups
_movie_guid_cache: Dict[str, Optional[str]] = {}

# Global cache for show GUIDs to avoid repeated lookups
_show_guid_cache: Dict[str, Optional[str]] = {}

# Global cache for ratings from Plex library sections
_ratings_cache: Dict[str, Dict[str, float]] = {}

# Paths for persistent state storage
CONFIG_DIR = os.environ.get("PLEXYTRACK_CONFIG_DIR", "/config")
STATE_DIR = os.environ.get("PLEXYTRACK_STATE_DIR", "/state")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LEGACY_STATE_FILE = os.path.join(CONFIG_DIR, "state.json")
STATE_SCHEMA_VERSION = 2


def migrate_legacy_state() -> None:
    """Migrate schema 1 state files to schema 2 layout if needed."""
    legacy_path = None

    if os.path.exists(LEGACY_STATE_FILE):
        legacy_path = LEGACY_STATE_FILE
    elif os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "schema" not in data:
                legacy_path = STATE_FILE
        except Exception:  # noqa: BLE001
            legacy_path = STATE_FILE

    if not legacy_path:
        return

    try:
        with open(legacy_path, "r", encoding="utf-8") as f:
            legacy = json.load(f)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to read legacy state file: %s", exc)
        return

    new_data = {
        "schema": STATE_SCHEMA_VERSION,
        "lastSync": legacy.get("lastSync"),
        "guid_cache": legacy.get("guid_cache", {}),
    }

    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(new_data, f, indent=2)
        if legacy_path != STATE_FILE and os.path.exists(legacy_path):
            os.remove(legacy_path)
        logger.info("Migrated legacy state to schema 2.")
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to migrate legacy state: %s", exc)


def _load_state() -> Dict[str, dict]:
    """Load persistent state from :data:`STATE_FILE`."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("schema") == STATE_SCHEMA_VERSION:
                return data
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to load state file: %s", exc)
    return {"schema": STATE_SCHEMA_VERSION, "lastSync": None, "guid_cache": {}}


def _save_state(data: Dict[str, dict]) -> None:
    """Persist ``data`` to :data:`STATE_FILE`."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Failed to save state file: %s", exc)


def load_state() -> Dict[str, dict]:
    """Public helper to load the entire state."""
    return _load_state()


def save_state(state: Dict[str, dict]) -> None:
    """Public helper to persist the entire state."""
    _save_state(state)


def load_last_plex_sync() -> Optional[str]:
    """Return the timestamp of the last successful Plex sync if available."""
    return _load_state().get("lastSync")


def save_last_plex_sync(timestamp: str) -> None:
    """Persist ``timestamp`` as the last successful Plex sync time."""
    state = _load_state()
    state["lastSync"] = timestamp
    _save_state(state)

def reset_movie_guid_cache():
    """Reset the global movie GUID cache"""
    global _movie_guid_cache
    _movie_guid_cache.clear()
    logger.debug("Movie GUID cache cleared")

def reset_show_guid_cache():
    """Reset the global show GUID cache"""
    global _show_guid_cache
    _show_guid_cache.clear()
    logger.debug("Show GUID cache cleared")

def get_cached_movie_guid(movie_title: str, movie_year: Optional[int], plex_item=None) -> Optional[str]:
    """
    Get movie GUID from cache or fetch it if not cached.
    
    Args:
        movie_title: Title of the movie
        movie_year: Year of the movie
        plex_item: Plex movie item if available
    
    Returns:
        Movie GUID if found, None otherwise
    """
    global _movie_guid_cache
    
    # Create a cache key from title and year
    cache_key = f"{movie_title}|{movie_year}"
    
    # Check cache first
    if cache_key in _movie_guid_cache:
        return _movie_guid_cache[cache_key]
    
    # If we have the plex item, get GUID directly
    guid = None
    if plex_item:
        guid = imdb_guid(plex_item)
    
    # Cache the result (even if None)
    _movie_guid_cache[cache_key] = guid
    return guid


def get_owner_watch_counts(account) -> Dict[str, int]:
    """
    Get watch counts for the owner using MyPlexAccount.
    
    Args:
        account: MyPlexAccount instance
    
    Returns:
        Dict with movies, episodes, and total counts
    """
    movies, episodes = get_owner_plex_history(account)
    return {
        "movies": len(movies),
        "episodes": len(episodes),
        "total": len(movies) + len(episodes),
    }


def get_managed_user_watch_counts(account, user_id) -> Dict[str, int]:
    """
    Get watch counts for a managed user using the new schema.
    
    Args:
        account: MyPlexAccount instance
        user_id: User ID of the managed user
    
    Returns:
        Dict with movies, episodes, and total counts
    """
    movies, episodes = get_managed_user_plex_history(account, user_id)
    return {
        "movies": len(movies),
        "episodes": len(episodes),
        "total": len(movies) + len(episodes),
    }


def get_owner_plex_history(account, mindate: Optional[str] = None) -> Tuple[
    Dict[str, Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """
    Return watched movies and episodes from Plex for the owner using MyPlexAccount.
    Follows the new schema: account.history()
    
    Args:
        account: MyPlexAccount instance
        mindate: Optional ISO timestamp string to only fetch items newer than this date
    
    Returns:
        Tuple of (movies_dict, episodes_dict) keyed by GUID
    """
    movies: Dict[str, Dict[str, Optional[str]]] = {}
    episodes: Dict[str, Dict[str, Optional[str]]] = {}

    logger.info(
        "Fetching owner history using MyPlexAccount%s",
        f" since {mindate}" if mindate else " (full sync)",
    )

    try:
        # Get owner history, optionally filtered by mindate
        history_items = account.history(mindate=mindate, maxresults=None)

        for entry in history_items:
            watched_at = to_iso_z(getattr(entry, "viewedAt", None))
            if mindate and not safe_timestamp_compare(watched_at, mindate):
                continue

            if entry.type == "movie":
                try:
                    item = entry.source() if hasattr(entry, 'source') else None
                    if not item:
                        continue
                    title = item.title
                    year = normalize_year(getattr(item, "year", None))
                    guid = get_cached_movie_guid(title, year, item)
                    if not guid:
                        continue
                    if guid not in movies:
                        movies[guid] = {
                            "title": title,
                            "year": year,
                            "watched_at": watched_at,
                            "guid": guid,
                        }
                except Exception as exc:
                    logger.debug("Failed to fetch movie from owner history: %s", exc)
                    continue
                    
            elif entry.type == "episode":
                try:
                    season = getattr(entry, "parentIndex", None)
                    number = getattr(entry, "index", None)
                    show = getattr(entry, "grandparentTitle", None)
                    
                    item = entry.source() if hasattr(entry, 'source') else None
                    if item:
                        season = season or getattr(item, 'seasonNumber', None)
                        number = number or getattr(item, 'index', None)
                        show = show or getattr(item, 'grandparentTitle', None)
                        guid = imdb_guid(item)
                    else:
                        guid = None
                        
                    if None in (season, number, show):
                        continue
                    code = f"S{int(season):02d}E{int(number):02d}"

                    # Only store episodes with individual episode GUIDs
                    if guid and valid_guid(guid) and guid not in episodes:
                        episodes[guid] = {
                            "show": show,
                            "code": code,
                            "watched_at": watched_at,
                            "guid": guid,
                        }
                except Exception as exc:
                    logger.debug("Failed to fetch episode from owner history: %s", exc)
                    continue

    except Exception as exc:
        logger.error("Failed to fetch owner history: %s", exc)

    # Escanear elementos marcados manualmente como vistos (viewCount > 0)
    logger.info("Scanning for manually marked watched items for owner...")
    try:
        # Obtener el servidor principal del owner
        server_name = os.environ.get("PLEX_SERVER_NAME")
        plex_server = None
        if server_name:
            try:
                plex_server = account.server(server_name)
                logger.debug("Successfully got server %s for owner", server_name)
            except Exception as exc:
                logger.warning("Failed to get specific server %s for owner: %s", server_name, exc)
        if not plex_server:
            try:
                resources = account.resources()
                for resource in resources:
                    if resource.provides and "server" in resource.provides:
                        plex_server = resource.connect()
                        logger.info("Using first available server: %s", plex_server.friendlyName)
                        break
            except Exception as exc:
                logger.warning("Failed to get any server for owner: %s", exc)
        if plex_server:
            for section in plex_server.library.sections():
                logger.debug("Processing section: %s (type: %s)", section.title, section.type)
                if section.type == "movie":
                    try:
                        watched_movies = section.search(viewCount__gt=0)
                        logger.debug("Found %d watched movies in section %s", len(watched_movies), section.title)
                        for movie in watched_movies:
                            try:
                                title = movie.title
                                year = normalize_year(getattr(movie, "year", None))
                                guid = get_cached_movie_guid(title, year, movie)
                                if not guid or guid in movies:
                                    continue
                                # Buscar si hay historial para este ítem (solo para el owner)
                                user_history_for_movie = list(
                                    plex_server.history(
                                        ratingKey=movie.ratingKey,
                                        mindate=mindate,
                                        maxresults=1,
                                        accountID=account.id,
                                    )
                                )
                                if user_history_for_movie:
                                    last_viewed = user_history_for_movie[0]
                                    watched_at = to_iso_z(getattr(last_viewed, "viewedAt", None))
                                else:
                                    # Manually marked as watched but no history entry
                                    # Use dateAdded or updatedAt as fallback timestamp
                                    fallback_date = getattr(movie, 'updatedAt', None) or getattr(movie, 'addedAt', None)
                                    watched_at = to_iso_z(fallback_date)

                                if mindate and not safe_timestamp_compare(watched_at, mindate):
                                    continue

                                movies[guid] = {
                                    "title": title,
                                    "year": year,
                                    "watched_at": watched_at,
                                    "guid": guid,
                                }
                                logger.debug("Added manually marked - Movie: %s (%s)", title, year)
                            except Exception as exc:
                                logger.debug("Failed to check movie %s for owner: %s", movie.ratingKey, exc)
                    except Exception as exc:
                        logger.warning("Failed to process movie section %s: %s", section.title, exc)
                elif section.type == "show":
                    try:
                        watched_episodes = section.searchEpisodes(viewCount__gt=0)
                        logger.debug("Found %d watched episodes in section %s", len(watched_episodes), section.title)
                        for episode in watched_episodes:
                            try:
                                guid = imdb_guid(episode)
                                season_num = getattr(episode, 'seasonNumber', None)
                                episode_num = getattr(episode, 'episodeNumber', None)
                                show_title = getattr(episode, 'grandparentTitle', None)
                                if None in (season_num, episode_num, show_title):
                                    continue
                                code = f"S{int(season_num):02d}E{int(episode_num):02d}"
                                if not guid or not valid_guid(guid) or guid in episodes:
                                    continue
                                user_history_for_ep = list(
                                    plex_server.history(
                                        ratingKey=episode.ratingKey,
                                        mindate=mindate,
                                        maxresults=1,
                                        accountID=account.id,
                                    )
                                )
                                if user_history_for_ep:
                                    last_viewed = user_history_for_ep[0]
                                    watched_at = to_iso_z(getattr(last_viewed, "viewedAt", None))
                                else:
                                    # Manually marked as watched but no history entry
                                    # Use dateAdded or updatedAt as fallback timestamp
                                    fallback_date = getattr(episode, 'updatedAt', None) or getattr(episode, 'addedAt', None)
                                    watched_at = to_iso_z(fallback_date)

                                if mindate and not safe_timestamp_compare(watched_at, mindate):
                                    continue

                                episodes[guid] = {
                                    "show": show_title,
                                    "code": code,
                                    "watched_at": watched_at,
                                    "guid": guid,
                                }
                                logger.debug("Added manually marked - Episode: %s %s", show_title, code)
                            except Exception as exc:
                                logger.debug("Failed to check episode %s for owner: %s", episode.ratingKey, exc)
                    except Exception as exc:
                        logger.warning("Failed to process show section %s: %s", section.title, exc)
    except Exception as exc:
        logger.error("Failed to scan libraries for owner: %s", exc)

    logger.info("Owner history: %d movies and %d episodes", len(movies), len(episodes))
    return movies, episodes


def get_managed_user_plex_history(account, user_id, server_name=None, mindate: Optional[str] = None) -> Tuple[
    Dict[str, Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """
    Return watched movies and episodes from Plex for a managed user.
    Uses the owner's credentials and filters by accountID as managed users
    cannot access their own history directly due to Plex permission model.
    
    IMPORTANT: This function uses the OWNER'S account credentials to fetch
    managed user history by filtering with accountID. This is the correct
    approach as per Plex API documentation - managed users don't have
    permission to access their own history directly.
    
    Args:
        account: MyPlexAccount instance (owner account)
        user_id: User ID of the managed user
        server_name: Name of the Plex server (optional)
        mindate: Optional ISO timestamp string to only fetch items newer than this date
    
    Returns:
        Tuple of (movies_dict, episodes_dict) keyed by GUID
    """
    movies: Dict[str, Dict[str, Optional[str]]] = {}
    episodes: Dict[str, Dict[str, Optional[str]]] = {}
    
    logger.info(
        "Fetching history for managed user ID: %s using owner credentials%s",
        user_id,
        f" since {mindate}" if mindate else " (full sync)",
    )
    
    try:
        # Find the managed user by ID to verify they exist
        managed_user = None
        for user in account.users():
            if user.id == user_id and hasattr(user, 'home') and user.home:
                managed_user = user
                break
        
        if not managed_user:
            logger.error("Managed user with ID %s not found", user_id)
            return movies, episodes
        
        logger.info("Found managed user: %s", managed_user.username or managed_user.title)
        
        # Get owner's server connection (owner has permissions to access all user data)
        plex_server = None
        server_name = server_name or os.environ.get("PLEX_SERVER_NAME")
        logger.debug("PLEX_SERVER_NAME environment variable: %s", server_name)
        
        if server_name:
            try:
                plex_server = account.resource(server_name).connect()
                logger.debug("Successfully connected to server %s using owner credentials", server_name)
            except Exception as exc:
                logger.warning("Failed to connect to specific server %s: %s", server_name, exc)
        
        if not plex_server:
            try:
                resources = account.resources()
                for resource in resources:
                    if resource.provides and "server" in resource.provides:
                        plex_server = resource.connect()
                        logger.info("Using first available server: %s", plex_server.friendlyName)
                        break
            except Exception as exc:
                logger.warning("Failed to connect to any server: %s", exc)
        
        if not plex_server:
            logger.error("No Plex server available for owner account")
            return movies, episodes
        
        # Method 1: Get global history filtered by accountID (most reliable)
        try:
            logger.debug("Fetching global history filtered by accountID %s", user_id)
            # Use owner's server to get history filtered by managed user's accountID
            history_items = plex_server.history(
                accountID=user_id, mindate=mindate, maxresults=None
            )
            
            for entry in history_items:
                watched_at = to_iso_z(getattr(entry, "viewedAt", None))
                if mindate and not safe_timestamp_compare(watched_at, mindate):
                    continue
                
                if entry.type == "movie":
                    try:
                        item = entry.source() if hasattr(entry, 'source') else None
                        if not item:
                            continue
                        title = item.title
                        year = normalize_year(getattr(item, "year", None))
                        guid = get_cached_movie_guid(title, year, item)
                        if not guid:
                            continue
                        if guid not in movies:
                            movies[guid] = {
                                "title": title,
                                "year": year,
                                "watched_at": watched_at,
                                "guid": guid,
                            }
                            logger.debug("Added from global history - Movie: %s (%s)", title, year)
                    except Exception as exc:
                        logger.debug("Failed to process movie from global history: %s", exc)
                        continue
                        
                elif entry.type == "episode":
                    try:
                        season = getattr(entry, "parentIndex", None)
                        number = getattr(entry, "index", None)
                        show = getattr(entry, "grandparentTitle", None)
                        
                        item = entry.source() if hasattr(entry, 'source') else None
                        if item:
                            season = season or getattr(item, 'seasonNumber', None)
                            number = number or getattr(item, 'index', None)
                            show = show or getattr(item, 'grandparentTitle', None)
                            guid = imdb_guid(item)
                        else:
                            guid = None
                            
                        if None in (season, number, show):
                            continue
                        code = f"S{int(season):02d}E{int(number):02d}"
                        
                        if guid and valid_guid(guid) and guid not in episodes:
                            episodes[guid] = {
                                "show": show,
                                "code": code,
                                "watched_at": watched_at,
                                "guid": guid,
                            }
                            logger.debug("Added from global history - Episode: %s %s", show, code)
                    except Exception as exc:
                        logger.debug("Failed to process episode from global history: %s", exc)
                        continue
                        
        except Exception as exc:
            logger.warning("Failed to get global history for managed user %s: %s", user_id, exc)
        
        # Method 2: Scan library sections for manually marked items (viewCount > 0) 
        # and verify they have history entries for this specific user
        try:
            logger.debug("Scanning library sections for manually marked items for user %s", user_id)
            
            for section in plex_server.library.sections():
                logger.debug("Processing section: %s (type: %s)", section.title, section.type)
                
                if section.type == "movie":
                    try:
                        # Get all movies marked as watched (viewCount > 0)
                        watched_movies = section.search(viewCount__gt=0)
                        logger.debug("Found %d watched movies in section %s", len(watched_movies), section.title)
                        
                        for movie in watched_movies:
                            try:
                                # Check if this specific user has history for this movie
                                user_history_for_movie = list(
                                    plex_server.history(
                                        ratingKey=movie.ratingKey,
                                        accountID=user_id,
                                        mindate=mindate,
                                        maxresults=1,
                                    )
                                )
                                
                                # Only include if this specific user has actually watched it
                                if user_history_for_movie:
                                    title = movie.title
                                    year = normalize_year(getattr(movie, "year", None))
                                    guid = get_cached_movie_guid(title, year, movie)

                                    if not guid or guid in movies:
                                        continue

                                    last_viewed = user_history_for_movie[0]
                                    watched_at = to_iso_z(getattr(last_viewed, "viewedAt", None))

                                    # If no timestamp in history, use fallback
                                    if not watched_at:
                                        fallback_date = getattr(movie, 'updatedAt', None) or getattr(movie, 'addedAt', None)
                                        watched_at = to_iso_z(fallback_date)
                                        logger.debug(
                                            "Added manually marked movie with fallback timestamp - Movie: %s (%s)",
                                            title,
                                            year,
                                        )
                                    else:
                                        logger.debug(
                                            "Added from section scan with history - Movie: %s (%s)",
                                            title,
                                            year,
                                        )

                                    if mindate and not safe_timestamp_compare(watched_at, mindate):
                                        continue

                                    movies[guid] = {
                                        "title": title,
                                        "year": year,
                                        "watched_at": watched_at,
                                        "guid": guid,
                                    }
                                    
                            except Exception as exc:
                                logger.debug("Failed to check movie %s for user %s: %s", movie.ratingKey, user_id, exc)
                                
                    except Exception as exc:
                        logger.warning("Failed to process movie section %s: %s", section.title, exc)
                        
                elif section.type == "show":
                    try:
                        # Get all episodes marked as watched (viewCount > 0)
                        watched_episodes = section.searchEpisodes(viewCount__gt=0)
                        logger.debug("Found %d watched episodes in section %s", len(watched_episodes), section.title)
                        
                        for episode in watched_episodes:
                            try:
                                # Check if this specific user has history for this episode
                                user_history_for_ep = list(
                                    plex_server.history(
                                        ratingKey=episode.ratingKey,
                                        accountID=user_id,
                                        mindate=mindate,
                                        maxresults=1,
                                    )
                                )
                                
                                # Only include if this specific user has actually watched it
                                if user_history_for_ep:
                                    season_num = getattr(episode, 'seasonNumber', None)
                                    episode_num = getattr(episode, 'episodeNumber', None)
                                    show_title = getattr(episode, 'grandparentTitle', None)

                                    if None in (season_num, episode_num, show_title):
                                        continue

                                    code = f"S{int(season_num):02d}E{int(episode_num):02d}"
                                    guid = imdb_guid(episode)

                                    if not guid or not valid_guid(guid) or guid in episodes:
                                        continue

                                    last_viewed = user_history_for_ep[0]
                                    watched_at = to_iso_z(getattr(last_viewed, "viewedAt", None))

                                    # If no timestamp in history, use fallback
                                    if not watched_at:
                                        fallback_date = getattr(episode, 'updatedAt', None) or getattr(episode, 'addedAt', None)
                                        watched_at = to_iso_z(fallback_date)
                                        logger.debug(
                                            "Added manually marked episode with fallback timestamp - Episode: %s %s",
                                            show_title,
                                            code,
                                        )
                                    else:
                                        logger.debug(
                                            "Added from section scan with history - Episode: %s %s",
                                            show_title,
        
                                            code,
                                        )

                                    if mindate and not safe_timestamp_compare(watched_at, mindate):
                                        continue

                                    episodes[guid] = {
                                        "show": show_title,
                                        "code": code,
                                        "watched_at": watched_at,
                                        "guid": guid,
                                    }
                                    
                            except Exception as exc:
                                logger.debug("Failed to check episode %s for user %s: %s", episode.ratingKey, user_id, exc)
                                
                    except Exception as exc:
                        logger.warning("Failed to process show section %s: %s", section.title, exc)
                        
        except Exception as exc:
            logger.error("Failed to scan libraries for managed user %s: %s", user_id, exc)
            
    except Exception as exc:
        logger.error("Failed to fetch managed user history: %s", exc)
        
    logger.info("Managed user %s history: %d movies and %d episodes", user_id, len(movies), len(episodes))
    
    if len(movies) == 0 and len(episodes) == 0:
        logger.warning("No content found for managed user %s - this might indicate a configuration issue", user_id)
        logger.warning("Recommendations:")
        logger.warning("1. Check if PLEX_SERVER_NAME environment variable is set correctly")
        logger.warning("2. Verify that the managed user has access to the server")
        logger.warning("3. Ensure the user has watched or marked content as watched")
        logger.warning("4. Check Plex server connectivity")
        logger.warning("5. Verify the owner account has proper access to the managed user's data")
        logger.warning("6. Confirm the managed user ID (%s) is correct", user_id)
        logger.warning("7. Check if the user has actually watched content (not just added to library)")
    else:
        logger.info("Successfully retrieved content for managed user %s", user_id)
        
    return movies, episodes


def get_plex_history(plex, mindate: Optional[str] = None) -> Tuple[
    Dict[str, Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """
    Legacy function for backward compatibility.
    Now redirects to get_owner_plex_history using the global account.
    Falls back to original server-based method if no account available.
    """
    from app import get_plex_account
    
    account = get_plex_account()
    if account is not None:
        # Use new schema with MyPlexAccount
        return get_owner_plex_history(account, mindate=mindate)
    else:
        # Fallback to legacy server-based method (when using token)
        logger.warning("No Plex account available, using legacy server-based history")
        return get_server_based_history(plex, mindate=mindate)


def get_user_plex_history(plex, user_id=None, mindate: Optional[str] = None) -> Tuple[
    Dict[str, Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """
    Legacy function for backward compatibility.
    Now redirects to new schema functions.
    """
    from app import get_plex_account
    
    account = get_plex_account()
    if account is not None:
        # Use new schema with MyPlexAccount
        if user_id is None:
            # For owner, use owner history
            return get_owner_plex_history(account, mindate=mindate)
        else:
            # For managed users, use managed user history
            return get_managed_user_plex_history(account, user_id, mindate=mindate)
    else:
        # Fallback to legacy server-based method (when using token)
        logger.warning("No Plex account available, using legacy server-based history for user %s", user_id)
        if user_id is None:
            return get_server_based_history(plex, mindate=mindate)
        else:
            # For legacy token method, we can't access user-specific history easily
            logger.error("Cannot access user-specific history with legacy token method")
            return {}, {}


def get_user_watch_counts(plex, user_id=None) -> Dict[str, int]:
    """
    Legacy function for backward compatibility.
    Get simplified watch counts for a user using the new schema.
    """
    from app import get_plex_account
    
    account = get_plex_account()
    if account is not None:
        if user_id is None:
            return get_owner_watch_counts(account)
        else:
            return get_managed_user_watch_counts(account, user_id)
    else:
        # Fallback to legacy method
        movies, episodes = get_server_based_history(plex)
        return {
            "movies": len(movies),
            "episodes": len(episodes),
            "total": len(movies) + len(episodes),
        }


def get_server_based_history(plex, mindate: Optional[str] = None) -> Tuple[
    Dict[str, Dict[str, Optional[str]]],
    Dict[str, Dict[str, Optional[str]]],
]:
    """
    Fallback method using direct server access (legacy token method).
    This is the original implementation that works with PlexServer tokens.
    Supports incremental sync via ``mindate`` when available.
    """
    movies: Dict[str, Dict[str, Optional[str]]] = {}
    episodes: Dict[str, Dict[str, Optional[str]]] = {}

    logger.info(
        "Fetching Plex history using server-based method%s",
        f" since {mindate}" if mindate else " (full sync)",
    )
    try:
        for entry in plex.history(mindate=mindate):
            watched_at = to_iso_z(getattr(entry, "viewedAt", None))
            if mindate and not safe_timestamp_compare(watched_at, mindate):
                continue

            if entry.type == "movie":
                try:
                    item = entry.source() or plex.fetchItem(entry.ratingKey)
                    title = item.title
                    year = normalize_year(getattr(item, "year", None))
                    guid = get_cached_movie_guid(title, year, item)
                    if not guid:
                        continue
                    if guid not in movies:
                        movies[guid] = {
                            "title": title,
                            "year": year,
                            "watched_at": watched_at,
                            "guid": guid,
                        }
                except Exception as exc:
                    logger.debug("Failed to fetch movie %s from Plex: %s", entry.ratingKey, exc)
                    continue
                    
            elif entry.type == "episode":
                try:
                    season = getattr(entry, "parentIndex", None)
                    number = getattr(entry, "index", None)
                    show = getattr(entry, "grandparentTitle", None)
                    
                    item = entry.source() or plex.fetchItem(entry.ratingKey)
                    if item:
                        season = season or item.seasonNumber
                        number = number or item.index
                        show = show or item.grandparentTitle
                        guid = imdb_guid(item)
                    else:
                        guid = None
                        
                    if None in (season, number, show):
                        continue
                    code = f"S{int(season):02d}E{int(number):02d}"

                    # Cache show GUID
                    series_guid: Optional[str] = None
                    if item is not None:
                        gp_guid_raw = getattr(item, "grandparentGuid", None)
                        if gp_guid_raw:
                            series_guid = _parse_guid_value(gp_guid_raw)
                    if series_guid is None and show in _show_guid_cache:
                        series_guid = _show_guid_cache[show]
                    if series_guid is None and show:
                        series_obj = get_show_from_library(plex, show)
                        series_guid = imdb_guid(series_obj) if series_obj else None
                        _show_guid_cache[show] = series_guid

                    # Only store episodes with individual episode GUIDs
                    if guid and valid_guid(guid) and guid not in episodes:
                        episodes[guid] = {
                            "show": show,
                            "code": code,
                            "watched_at": watched_at,
                            "guid": guid,
                        }
                except Exception as exc:
                    logger.debug("Failed to fetch episode %s from Plex: %s", entry.ratingKey, exc)
                    continue

        # Also check library for watched flags
        logger.info("Fetching watched flags from Plex library…")
        for section in plex.library.sections():
            try:
                if section.type == "movie":
                    for item in section.search(viewCount__gt=0):
                        title = item.title
                        year = normalize_year(getattr(item, "year", None))
                        guid = get_cached_movie_guid(title, year, item)
                        if guid and guid not in movies:
                            watched_at = to_iso_z(getattr(item, "lastViewedAt", None))
                            if mindate and not safe_timestamp_compare(watched_at, mindate):
                                continue
                            movies[guid] = {
                                "title": title,
                                "year": year,
                                "watched_at": watched_at,
                                "guid": guid,
                            }
                elif section.type == "show":
                    for ep in section.searchEpisodes(viewCount__gt=0):
                        code = f"S{int(ep.seasonNumber):02d}E{int(ep.episodeNumber):02d}"
                        guid = imdb_guid(ep)
                        show_title = getattr(ep, "grandparentTitle", None)
                        # Only store episodes with individual episode GUIDs
                        if guid and guid not in episodes:
                            watched_at = to_iso_z(getattr(ep, "lastViewedAt", None))
                            if mindate and not safe_timestamp_compare(watched_at, mindate):
                                continue
                            episodes[guid] = {
                                "show": show_title,
                                "code": code,
                                "watched_at": watched_at,
                                "guid": guid,
                            }
            except Exception as exc:
                logger.debug("Failed fetching watched items from section %s: %s", section.title, exc)

    except Exception as exc:
        logger.error("Failed to fetch server-based history: %s", exc)

    logger.info("Server-based history: %d movies and %d episodes", len(movies), len(episodes))
    return movies, episodes


def update_plex(
    plex,
    movies: Set[Tuple[str, Optional[int], Optional[str]]],
    episodes: Set[Tuple[str, str, Optional[str]]],  # Only allow str for key, not Tuple fallback
) -> None:
    """Mark items as watched in Plex when missing."""
    movie_count = 0
    episode_count = 0

    for title, year, guid in movies:
        if guid and valid_guid(guid):
            try:
                item = find_item_by_guid(plex, guid)
                if item and getattr(item, "isWatched", lambda: bool(getattr(item, "viewCount", 0)))():
                    continue
                if item:
                    item.markWatched()
                    movie_count += 1
                    continue
            except Exception as exc:
                logger.debug("GUID search failed for %s: %s", guid, exc)

        found = None
        for section in plex.library.sections():
            if section.type != "movie":
                continue
            try:
                results = section.search(title=title)
                for candidate in results:
                    if year is None or normalize_year(getattr(candidate, "year", None)) == normalize_year(year):
                        found = candidate
                        break
                if found:
                    break
            except Exception as exc:
                logger.debug("Search failed in section %s: %s", section.title, exc)

        if not found:
            logger.debug("Movie not found in Plex library: %s (%s)", title, year)
            continue

        try:
            # Check if already watched using isWatched property or viewCount
            is_watched = getattr(found, "isWatched", False) or bool(getattr(found, "viewCount", 0))
            if is_watched:
                continue
            found.markWatched()
            movie_count += 1
        except Exception as exc:
            logger.debug("Failed to mark movie '%s' as watched: %s", found.title, exc)

    for show_title, code, key in episodes:
        guid: Optional[str] = None
        if isinstance(key, str):
            guid = key if valid_guid(key) else None
        # Remove tuple fallback for Trakt, only allow for Simkl (not present here)

        if guid:
            try:
                item = find_item_by_guid(plex, guid)
                if item:
                    # Check if already watched using isWatched property or viewCount
                    is_watched = getattr(item, "isWatched", False) or bool(getattr(item, "viewCount", 0))
                    if is_watched:
                        continue
                    item.markWatched()
                    episode_count += 1
                    continue
            except Exception as exc:
                logger.debug("GUID search failed for %s: %s", guid, exc)

        try:
            season_num, episode_num = map(int, code.upper().lstrip("S").split("E"))
        except ValueError:
            logger.debug("Invalid episode code format: %s", code)
            continue

        show_obj = get_show_from_library(plex, show_title)
        if not show_obj:
            logger.debug("Show not found in Plex library: %s", show_title)
            continue

        try:
            # Try to find the episode using the show's episode method
            ep_obj = show_obj.episode(season=season_num, episode=episode_num)
            # Check if already watched using isWatched property or viewCount
            is_watched = getattr(ep_obj, "isWatched", False) or bool(getattr(ep_obj, "viewCount", 0))
            if is_watched:
                continue
            ep_obj.markWatched()
            episode_count += 1
        except Exception as exc:
            logger.debug("Failed marking episode %s - %s as watched: %s", show_title, code, exc)

    if movie_count or episode_count:
        logger.info("Marked %d movies and %d episodes as watched in Plex", movie_count, episode_count)
    else:
        logger.info("Nothing new to send to Plex.")


def get_cached_ratings(plex) -> Dict[str, Dict[str, float]]:
    """
    Get cached ratings from all Plex library sections for better performance.
    
    Returns a dictionary where:
    - Keys are section keys (string)
    - Values are dictionaries mapping rating keys to user ratings
    
    Args:
        plex: PlexServer instance
        
    Returns:
        Dict mapping section keys to {rating_key: user_rating} dictionaries
    """
    cached_ratings: Dict[str, Dict[str, float]] = {}
    
    logger.debug("Caching ratings from all Plex library sections...")
    
    try:
        for section in plex.library.sections():
            section_key = str(section.key)
            section_ratings: Dict[str, float] = {}
            
            logger.debug("Processing ratings for section: %s (key: %s)", section.title, section_key)
            
            try:
                # Get all items in the section that have user ratings
                if section.type == "movie":
                    # For movies, get all rated movies
                    all_items = section.search(userRating__gte=0.5)
                elif section.type == "show":
                    # For shows, get rated shows, seasons, and episodes
                    all_items = section.search(userRating__gte=0.5)
                else:
                    # For music and other types
                    all_items = section.search(userRating__gte=0.5)
                
                for item in all_items:
                    if hasattr(item, 'userRating') and item.userRating is not None:
                        section_ratings[str(item.ratingKey)] = float(item.userRating)
                
                cached_ratings[section_key] = section_ratings
                logger.debug("Cached %d ratings for section: %s", len(section_ratings), section.title)
                
            except Exception as exc:
                logger.warning("Failed to cache ratings for section %s: %s", section.title, exc)
                cached_ratings[section_key] = {}
                
    except Exception as exc:
        logger.error("Failed to cache ratings from Plex: %s", exc)
        return {}
    
    total_ratings = sum(len(ratings) for ratings in cached_ratings.values())
    logger.info("Successfully cached %d total ratings across %d sections", total_ratings, len(cached_ratings))
    
    return cached_ratings
