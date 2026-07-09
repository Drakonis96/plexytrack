"""Direct Trakt <-> Simkl bridge (connection #2 of the Plex/Trakt/Simkl mesh).

Mirrors ratings, watchlist and movie watch history **directly** between Trakt
and Simkl without routing through the Plex library, so data that originates on
one service (e.g. a rating added on the Trakt website, or a title added to the
Simkl plan-to-watch from the mobile app) propagates to the other.

Both services expose the same IMDb/TMDb/TVDb ids, which are used as the match
key, and every push is additive + idempotent (only items missing on the target
side are sent), so the bridge is safe to run repeatedly.

Intentionally excluded:
- Collection: Simkl has no collection concept distinct from its watched lists.
- Episode-level history: in dual-provider mode Plex already pushes episode
  history to both services; bridging it directly would duplicate that path and
  risk mismatched episode keys. Movie history is bridged here.
"""

import logging
from typing import Optional

from utils import guid_to_ids, normalize_year

from trakt_utils import (
    trakt_request,
    fetch_trakt_ratings,
    fetch_trakt_watchlist,
    fetch_trakt_history_full,
)
from simkl_utils import (
    simkl_request,
    fetch_simkl_ratings,
    get_simkl_watchlist,
    get_simkl_history,
    add_items_to_simkl_list,
)

logger = logging.getLogger(__name__)

BRIDGE_BOTH = "both"
BRIDGE_TRAKT_TO_SIMKL = "trakt_to_simkl"
BRIDGE_SIMKL_TO_TRAKT = "simkl_to_trakt"


def _ids_key(ids) -> Optional[str]:
    """Return a stable id key for an ids dict.

    Falls back to ``anidb`` so anime known only by its AniDB id (common for
    Plex/Simkl anime) can still be matched across services.
    """
    if not isinstance(ids, dict):
        return None
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
# Ratings
# ---------------------------------------------------------------------------


def _index_trakt_ratings(items) -> dict:
    idx = {}
    for it in items or []:
        typ = it.get("type")
        if typ not in ("movie", "show"):
            continue
        media = it.get(typ, {}) or {}
        key = _ids_key(media.get("ids", {}))
        if key and it.get("rating") is not None:
            idx[key] = {"type": typ, "ids": media.get("ids", {}), "rating": it["rating"]}
    return idx


def _index_simkl_ratings(items) -> dict:
    idx = {}
    for it in items or []:
        typ = it.get("type")
        if typ not in ("movie", "show"):
            continue
        key = _ids_key(it.get("ids", {}))
        if key and it.get("rating") is not None:
            idx[key] = {"type": typ, "ids": it.get("ids", {}), "rating": it["rating"]}
    return idx


def _push_ratings(request_fn, headers, items) -> int:
    movies = [{"ids": i["ids"], "rating": i["rating"]} for i in items if i["type"] == "movie"]
    shows = [{"ids": i["ids"], "rating": i["rating"]} for i in items if i["type"] == "show"]
    payload = {}
    if movies:
        payload["movies"] = movies
    if shows:
        payload["shows"] = shows
    if not payload:
        return 0
    request_fn("POST", "/sync/ratings", headers, json=payload)
    return len(movies) + len(shows)


def bridge_ratings(trakt_headers, simkl_headers, direction=BRIDGE_BOTH) -> int:
    """Mirror movie/show ratings between Trakt and Simkl. Returns items pushed."""
    trakt_idx = _index_trakt_ratings(fetch_trakt_ratings(trakt_headers))
    simkl_idx = _index_simkl_ratings(fetch_simkl_ratings(simkl_headers))

    pushed = 0
    if direction in (BRIDGE_BOTH, BRIDGE_TRAKT_TO_SIMKL):
        missing = [v for k, v in trakt_idx.items() if k not in simkl_idx]
        pushed += _push_ratings(simkl_request, simkl_headers, missing)
    if direction in (BRIDGE_BOTH, BRIDGE_SIMKL_TO_TRAKT):
        missing = [v for k, v in simkl_idx.items() if k not in trakt_idx]
        pushed += _push_ratings(trakt_request, trakt_headers, missing)
    if pushed:
        logger.info("Trakt<->Simkl ratings bridge propagated %d rating(s)", pushed)
    return pushed


# ---------------------------------------------------------------------------
# Watchlist  (Trakt watchlist  <->  Simkl plan-to-watch)
# ---------------------------------------------------------------------------


def _index_trakt_watchlist(data) -> dict:
    idx = {}
    for it in (data or {}).get("movies", []) or []:
        m = it.get("movie", {}) or {}
        key = _ids_key(m.get("ids", {}))
        if key:
            idx[key] = {"type": "movie", "ids": m.get("ids", {}),
                        "title": m.get("title"), "year": normalize_year(m.get("year"))}
    for it in (data or {}).get("shows", []) or []:
        s = it.get("show", {}) or {}
        key = _ids_key(s.get("ids", {}))
        if key:
            idx[key] = {"type": "show", "ids": s.get("ids", {}),
                        "title": s.get("title"), "year": normalize_year(s.get("year"))}
    return idx


def _index_simkl_plantowatch(data) -> dict:
    idx = {}
    for m in (data or {}).get("movies", []) or []:
        if (m.get("status") or m.get("list")) != "plantowatch":
            continue
        mv = m.get("movie", {}) or {}
        key = _ids_key(mv.get("ids", {}))
        if key:
            idx[key] = {"type": "movie", "ids": mv.get("ids", {}),
                        "title": mv.get("title"), "year": normalize_year(mv.get("year"))}
    for s in (data or {}).get("shows", []) or []:
        if (s.get("status") or s.get("list")) != "plantowatch":
            continue
        sh = s.get("show", {}) or {}
        key = _ids_key(sh.get("ids", {}))
        if key:
            idx[key] = {"type": "show", "ids": sh.get("ids", {}),
                        "title": sh.get("title"), "year": normalize_year(sh.get("year"))}
    return idx


def bridge_watchlist(trakt_headers, simkl_headers, direction=BRIDGE_BOTH) -> int:
    """Mirror Trakt watchlist <-> Simkl plan-to-watch. Returns items pushed."""
    trakt_idx = _index_trakt_watchlist(fetch_trakt_watchlist(trakt_headers))
    simkl_idx = _index_simkl_plantowatch(get_simkl_watchlist(simkl_headers))

    pushed = 0
    if direction in (BRIDGE_BOTH, BRIDGE_TRAKT_TO_SIMKL):
        missing = [v for k, v in trakt_idx.items() if k not in simkl_idx]
        movies = [{"ids": i["ids"], "title": i["title"], "year": i["year"]}
                  for i in missing if i["type"] == "movie"]
        shows = [{"ids": i["ids"], "title": i["title"], "year": i["year"]}
                 for i in missing if i["type"] == "show"]
        if movies or shows:
            add_items_to_simkl_list(
                simkl_headers,
                movies=movies or None,
                shows=shows or None,
                target_list="plantowatch",
            )
            pushed += len(movies) + len(shows)
    if direction in (BRIDGE_BOTH, BRIDGE_SIMKL_TO_TRAKT):
        missing = [v for k, v in simkl_idx.items() if k not in trakt_idx]
        movies = [{"ids": i["ids"]} for i in missing if i["type"] == "movie"]
        shows = [{"ids": i["ids"]} for i in missing if i["type"] == "show"]
        payload = {}
        if movies:
            payload["movies"] = movies
        if shows:
            payload["shows"] = shows
        if payload:
            trakt_request("POST", "/sync/watchlist", trakt_headers, json=payload)
            pushed += len(movies) + len(shows)
    if pushed:
        logger.info("Trakt<->Simkl watchlist bridge propagated %d item(s)", pushed)
    return pushed


# ---------------------------------------------------------------------------
# History (movies only – see module docstring)
# ---------------------------------------------------------------------------


def _index_trakt_movie_history(items) -> dict:
    idx = {}
    for it in items or []:
        if it.get("type") != "movie":
            continue
        m = it.get("movie", {}) or {}
        key = _ids_key(m.get("ids", {}))
        if key and key not in idx:
            idx[key] = {"ids": m.get("ids", {}), "watched_at": it.get("watched_at")}
    return idx


def bridge_history(trakt_headers, simkl_headers, direction=BRIDGE_BOTH) -> int:
    """Mirror movie watch history between Trakt and Simkl. Returns items pushed."""
    trakt_idx = _index_trakt_movie_history(fetch_trakt_history_full(trakt_headers))
    simkl_movies, _ = get_simkl_history(simkl_headers)  # {key: (title, year, watched_at)}

    pushed = 0
    if direction in (BRIDGE_BOTH, BRIDGE_TRAKT_TO_SIMKL):
        missing = [{"ids": v["ids"], "watched_at": v["watched_at"]}
                   for k, v in trakt_idx.items() if k not in simkl_movies]
        movies = [m for m in missing if m["ids"]]
        if movies:
            simkl_request("POST", "/sync/history", simkl_headers, json={"movies": movies})
            pushed += len(movies)
    if direction in (BRIDGE_BOTH, BRIDGE_SIMKL_TO_TRAKT):
        missing_keys = [k for k in simkl_movies if k not in trakt_idx]
        movies = []
        for key in missing_keys:
            ids = guid_to_ids(key)
            if not ids:
                continue
            watched_at = simkl_movies[key][2]
            obj = {"ids": ids}
            if watched_at:
                obj["watched_at"] = watched_at
            movies.append(obj)
        if movies:
            trakt_request("POST", "/sync/history", trakt_headers, json={"movies": movies})
            pushed += len(movies)
    if pushed:
        logger.info("Trakt<->Simkl history bridge propagated %d movie(s)", pushed)
    return pushed


def run_trakt_simkl_bridge(
    trakt_headers,
    simkl_headers,
    *,
    ratings: bool = True,
    watchlist: bool = True,
    history: bool = True,
    direction: str = BRIDGE_BOTH,
) -> dict:
    """Run the enabled bridges, isolating failures per data type.

    Returns a dict of ``{data_type: items_pushed}`` for the bridges that ran.
    """
    result = {}
    if ratings:
        try:
            result["ratings"] = bridge_ratings(trakt_headers, simkl_headers, direction)
        except Exception as exc:  # noqa: BLE001
            logger.error("Ratings bridge failed: %s", exc)
    if watchlist:
        try:
            result["watchlist"] = bridge_watchlist(trakt_headers, simkl_headers, direction)
        except Exception as exc:  # noqa: BLE001
            logger.error("Watchlist bridge failed: %s", exc)
    if history:
        try:
            result["history"] = bridge_history(trakt_headers, simkl_headers, direction)
        except Exception as exc:  # noqa: BLE001
            logger.error("History bridge failed: %s", exc)
    return result
