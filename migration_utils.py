import logging
from typing import List, Tuple, Dict, Optional

from trakt_utils import get_trakt_history, update_trakt
from simkl_utils import get_simkl_history, update_simkl

logger = logging.getLogger(__name__)


def trakt_to_simkl(
    trakt_headers: Dict[str, str], simkl_headers: Dict[str, str]
) -> None:
    """Sync all Trakt watched history to Simkl."""
    movies, episodes = get_trakt_history(trakt_headers)
    movie_list = [
        (title, year, guid, watched_at)
        for guid, (title, year, watched_at) in movies.items()
    ]
    episode_list = [
        (show, code, guid, watched_at)
        for guid, (show, code, watched_at) in episodes.items()
    ]
    update_simkl(simkl_headers, movie_list, episode_list)


def simkl_to_trakt(
    simkl_headers: Dict[str, str], trakt_headers: Dict[str, str]
) -> None:
    """Sync all Simkl watched history to Trakt."""
    movies, episodes = get_simkl_history(simkl_headers)
    movie_list = [
        (title, year, watched_at, guid)
        for guid, (title, year, watched_at) in movies.items()
    ]
    episode_list = [
        (show, code, watched_at, guid)
        for guid, (show, code, watched_at) in episodes.items()
    ]
    update_trakt(trakt_headers, movie_list, episode_list)
