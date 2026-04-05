"""
Thorough tests for the Simkl plan-to-watch fix in get_simkl_history().

Verifies that the /sync/all-items response is properly filtered by list
status so that only "completed" and "watching" items are treated as watched.
Items with status "plantowatch", "hold", or "dropped" must be excluded.

Covers:
  - Movies across all 5 list statuses
  - TV show episodes across all 5 list statuses
  - Full seasons (multiple episodes) with mixed statuses
  - Mixed responses with items in different statuses
  - Edge cases: missing "status" field, empty responses, null data
  - Fallback: items using "list" field instead of "status"
  - Interaction between /sync/history and /sync/all-items
  - Anime items with anidb IDs
  - Items with only TMDB, TVDB, or IMDB IDs
"""

import os
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, call

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from simkl_utils import get_simkl_history, simkl_movie_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer fake_token",
    "simkl-api-key": "fake_client_id",
}


def _mock_response(json_data=None, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.raise_for_status.return_value = None
    return resp


def _make_movie(title, year, imdb=None, tmdb=None, tvdb=None, anidb=None):
    ids = {}
    if imdb:
        ids["imdb"] = imdb
    if tmdb:
        ids["tmdb"] = tmdb
    if tvdb:
        ids["tvdb"] = tvdb
    if anidb:
        ids["anidb"] = anidb
    return {"title": title, "year": year, "ids": ids}


def _make_movie_item(movie, list_status, last_watched_at=None):
    item = {"movie": movie, "status": list_status}
    if last_watched_at:
        item["last_watched_at"] = last_watched_at
    return item


def _make_show(title, year=None, imdb=None, tmdb=None, tvdb=None, anidb=None):
    ids = {}
    if imdb:
        ids["imdb"] = imdb
    if tmdb:
        ids["tmdb"] = tmdb
    if tvdb:
        ids["tvdb"] = tvdb
    if anidb:
        ids["anidb"] = anidb
    show = {"title": title, "ids": ids}
    if year:
        show["year"] = year
    return show


def _make_episode(number, season=1, watched_at=None, plays=0, ids=None):
    ep = {"number": number, "season": season}
    if watched_at:
        ep["watched_at"] = watched_at
    if plays:
        ep["plays"] = plays
    if ids:
        ep["ids"] = ids
    return ep


def _make_season(number, episodes):
    return {"number": number, "episodes": episodes}


def _make_show_item(show, seasons, list_status, last_watched_at=None):
    item = {"show": show, "seasons": seasons, "status": list_status}
    if last_watched_at:
        item["last_watched_at"] = last_watched_at
    return item


def _build_all_items_response(movies=None, shows=None, anime=None):
    resp = {}
    if movies is not None:
        resp["movies"] = movies
    if shows is not None:
        resp["shows"] = shows
    if anime is not None:
        resp["anime"] = anime
    return resp


def _setup_mock(mock_req, history_movies=None, history_episodes=None, all_items=None):
    """Configure mock to return different responses for each simkl_request call.

    get_simkl_history makes 3 sequential calls:
      1. GET /sync/history (type=movies)
      2. GET /sync/history (type=episodes)
      3. GET /sync/all-items
    """
    mock_req.side_effect = [
        _mock_response(history_movies if history_movies is not None else []),
        _mock_response(history_episodes if history_episodes is not None else []),
        _mock_response(all_items if all_items is not None else {}),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# MOVIES – List status filtering
# ═══════════════════════════════════════════════════════════════════════════════


class TestMovieListStatusFiltering:
    """Movies from /sync/all-items must be filtered by list status."""

    @patch("simkl_utils.simkl_request")
    def test_completed_movie_is_included(self, mock_req):
        movie = _make_movie("Inception", 2010, imdb="tt1375666")
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-01-15T10:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, episodes = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt1375666" in movies
        assert movies["imdb://tt1375666"][0] == "Inception"
        assert movies["imdb://tt1375666"][1] == 2010
        assert movies["imdb://tt1375666"][2] == "2025-01-15T10:00:00Z"

    @patch("simkl_utils.simkl_request")
    def test_watching_movie_is_included(self, mock_req):
        movie = _make_movie("The Matrix", 1999, imdb="tt0133093")
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "watching", "2025-03-01T08:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt0133093" in movies

    @patch("simkl_utils.simkl_request")
    def test_plantowatch_movie_is_excluded(self, mock_req):
        movie = _make_movie("Dune Part Two", 2024, imdb="tt15239678")
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "plantowatch")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt15239678" not in movies
        assert len(movies) == 0

    @patch("simkl_utils.simkl_request")
    def test_hold_movie_is_excluded(self, mock_req):
        movie = _make_movie("Tenet", 2020, imdb="tt6723592")
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "hold")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt6723592" not in movies

    @patch("simkl_utils.simkl_request")
    def test_dropped_movie_is_excluded(self, mock_req):
        movie = _make_movie("Cats", 2019, imdb="tt5697572")
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "dropped")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt5697572" not in movies

    @patch("simkl_utils.simkl_request")
    def test_movie_missing_status_field_is_excluded(self, mock_req):
        """If the API response omits the 'status' field, the movie should NOT
        be treated as watched (safe default)."""
        movie = _make_movie("Unknown Status", 2023, imdb="tt9999999")
        item = {"movie": movie, "last_watched_at": "2025-01-01T00:00:00Z"}
        # No "status" or "list" key at all
        all_items = _build_all_items_response(movies=[item])
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt9999999" not in movies

    @patch("simkl_utils.simkl_request")
    def test_movie_empty_status_field_is_excluded(self, mock_req):
        movie = _make_movie("Empty Status", 2023, imdb="tt8888888")
        item = {"movie": movie, "status": "", "last_watched_at": "2025-01-01T00:00:00Z"}
        all_items = _build_all_items_response(movies=[item])
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt8888888" not in movies

    @patch("simkl_utils.simkl_request")
    def test_movie_with_list_field_fallback(self, mock_req):
        """If API uses 'list' instead of 'status', it should still work."""
        movie = _make_movie("List Fallback", 2023, imdb="tt7777777")
        item = {"movie": movie, "list": "completed", "last_watched_at": "2025-01-01T00:00:00Z"}
        all_items = _build_all_items_response(movies=[item])
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt7777777" in movies

    @patch("simkl_utils.simkl_request")
    def test_movie_with_list_field_plantowatch_excluded(self, mock_req):
        """If API uses 'list' field with plantowatch, should still be excluded."""
        movie = _make_movie("List PTW", 2023, imdb="tt6666666")
        item = {"movie": movie, "list": "plantowatch", "last_watched_at": "2025-01-01T00:00:00Z"}
        all_items = _build_all_items_response(movies=[item])
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt6666666" not in movies

    @patch("simkl_utils.simkl_request")
    def test_mixed_status_movies_only_watched_included(self, mock_req):
        """A response with movies in all 5 statuses should only include
        completed and watching."""
        movies_list = [
            _make_movie_item(
                _make_movie("Completed Movie", 2020, imdb="tt0000001"),
                "completed", "2025-01-01T00:00:00Z"
            ),
            _make_movie_item(
                _make_movie("Watching Movie", 2021, tmdb=100001),
                "watching", "2025-02-01T00:00:00Z"
            ),
            _make_movie_item(
                _make_movie("Plan To Watch Movie", 2022, imdb="tt0000003"),
                "plantowatch"
            ),
            _make_movie_item(
                _make_movie("On Hold Movie", 2023, tmdb=100004),
                "hold"
            ),
            _make_movie_item(
                _make_movie("Dropped Movie", 2019, imdb="tt0000005"),
                "dropped"
            ),
        ]
        all_items = _build_all_items_response(movies=movies_list)
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert len(movies) == 2
        assert "imdb://tt0000001" in movies
        assert "tmdb://100001" in movies
        assert "imdb://tt0000003" not in movies
        assert "tmdb://100004" not in movies
        assert "imdb://tt0000005" not in movies


# ═══════════════════════════════════════════════════════════════════════════════
# MOVIES – Different ID types
# ═══════════════════════════════════════════════════════════════════════════════


class TestMovieIDTypes:
    """Verify filtering works with all supported ID types."""

    @patch("simkl_utils.simkl_request")
    def test_tmdb_only_movie_completed(self, mock_req):
        movie = _make_movie("TMDB Movie", 2022, tmdb=555555)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-06-01T00:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "tmdb://555555" in movies

    @patch("simkl_utils.simkl_request")
    def test_tmdb_only_movie_plantowatch(self, mock_req):
        movie = _make_movie("TMDB PTW Movie", 2022, tmdb=555556)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "plantowatch")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "tmdb://555556" not in movies

    @patch("simkl_utils.simkl_request")
    def test_tvdb_only_movie_completed(self, mock_req):
        movie = _make_movie("TVDB Movie", 2021, tvdb=777777)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-05-01T00:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "tvdb://777777" in movies

    @patch("simkl_utils.simkl_request")
    def test_anidb_movie_plantowatch_excluded(self, mock_req):
        movie = _make_movie("Anime Movie", 2023, anidb=12345)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "plantowatch")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "anidb://12345" not in movies

    @patch("simkl_utils.simkl_request")
    def test_anidb_movie_completed_included(self, mock_req):
        movie = _make_movie("Spirited Away", 2001, anidb=112)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-04-01T00:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "anidb://112" in movies


# ═══════════════════════════════════════════════════════════════════════════════
# TV SHOWS – List status filtering (episodes)
# ═══════════════════════════════════════════════════════════════════════════════


class TestShowListStatusFiltering:
    """Episodes from /sync/all-items shows must be filtered by the show's
    list status."""

    @patch("simkl_utils.simkl_request")
    def test_completed_show_episodes_included(self, mock_req):
        show = _make_show("Breaking Bad", 2008, imdb="tt0903747")
        episodes = [
            _make_episode(1, season=1, watched_at="2025-02-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-02-02T12:00:00Z"),
            _make_episode(3, season=1, watched_at="2025-02-03T12:00:00Z"),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "completed", "2025-02-03T12:00:00Z")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 3
        codes = {v[1] for v in eps.values()}
        assert "S01E01" in codes
        assert "S01E02" in codes
        assert "S01E03" in codes

    @patch("simkl_utils.simkl_request")
    def test_watching_show_episodes_included(self, mock_req):
        show = _make_show("The Bear", 2022, imdb="tt14452776")
        episodes = [
            _make_episode(1, season=1, watched_at="2025-03-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-03-02T12:00:00Z"),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "watching")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 2

    @patch("simkl_utils.simkl_request")
    def test_plantowatch_show_episodes_excluded(self, mock_req):
        show = _make_show("Stranger Things", 2016, imdb="tt4574334")
        episodes = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-01-02T12:00:00Z"),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "plantowatch")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0

    @patch("simkl_utils.simkl_request")
    def test_hold_show_episodes_excluded(self, mock_req):
        show = _make_show("Lost", 2004, imdb="tt0411008")
        episodes = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "hold")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0

    @patch("simkl_utils.simkl_request")
    def test_dropped_show_episodes_excluded(self, mock_req):
        show = _make_show("The Walking Dead", 2010, imdb="tt1520211")
        episodes = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-01-02T12:00:00Z"),
            _make_episode(3, season=1, watched_at="2025-01-03T12:00:00Z"),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "dropped")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SEASONS – Multiple episodes per season
# ═══════════════════════════════════════════════════════════════════════════════


class TestFullSeasonFiltering:
    """Verify filtering works with full seasons (many episodes)."""

    @patch("simkl_utils.simkl_request")
    def test_completed_full_season_all_episodes_included(self, mock_req):
        show = _make_show("Game of Thrones", 2011, imdb="tt0944947")
        episodes = [
            _make_episode(i, season=1, watched_at=f"2025-01-{i:02d}T12:00:00Z")
            for i in range(1, 11)  # 10 episodes
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "completed")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 10
        codes = {v[1] for v in eps.values()}
        for i in range(1, 11):
            assert f"S01E{i:02d}" in codes

    @patch("simkl_utils.simkl_request")
    def test_plantowatch_full_season_all_episodes_excluded(self, mock_req):
        show = _make_show("House of the Dragon", 2022, imdb="tt11198330")
        episodes = [
            _make_episode(i, season=1, watched_at=f"2025-01-{i:02d}T12:00:00Z")
            for i in range(1, 11)
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "plantowatch")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0

    @patch("simkl_utils.simkl_request")
    def test_multiple_seasons_completed(self, mock_req):
        show = _make_show("The Office", 2005, imdb="tt0386676")
        s1_episodes = [
            _make_episode(i, season=1, watched_at=f"2025-01-{i:02d}T12:00:00Z")
            for i in range(1, 7)  # 6 episodes
        ]
        s2_episodes = [
            _make_episode(i, season=2, watched_at=f"2025-02-{i:02d}T12:00:00Z")
            for i in range(1, 23)  # 22 episodes
        ]
        seasons = [_make_season(1, s1_episodes), _make_season(2, s2_episodes)]
        show_item = _make_show_item(show, seasons, "completed")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 28  # 6 + 22

    @patch("simkl_utils.simkl_request")
    def test_multiple_seasons_plantowatch_all_excluded(self, mock_req):
        show = _make_show("Severance", 2022, tmdb=95396)
        s1_episodes = [
            _make_episode(i, season=1, watched_at=f"2025-01-{i:02d}T12:00:00Z")
            for i in range(1, 10)
        ]
        s2_episodes = [
            _make_episode(i, season=2, watched_at=f"2025-03-{i:02d}T12:00:00Z")
            for i in range(1, 11)
        ]
        seasons = [_make_season(1, s1_episodes), _make_season(2, s2_episodes)]
        show_item = _make_show_item(show, seasons, "plantowatch")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# MIXED SHOWS – Different shows with different statuses
# ═══════════════════════════════════════════════════════════════════════════════


class TestMixedShowStatuses:
    """Multiple shows in a single response with different list statuses."""

    @patch("simkl_utils.simkl_request")
    def test_mixed_shows_only_watched_statuses_episodes_included(self, mock_req):
        # Completed show
        completed_show = _make_show("Breaking Bad", 2008, imdb="tt0903747")
        completed_eps = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-01-02T12:00:00Z"),
        ]
        completed_item = _make_show_item(
            completed_show, [_make_season(1, completed_eps)], "completed"
        )

        # Watching show
        watching_show = _make_show("The Bear", 2022, imdb="tt14452776")
        watching_eps = [
            _make_episode(1, season=1, watched_at="2025-02-01T12:00:00Z"),
        ]
        watching_item = _make_show_item(
            watching_show, [_make_season(1, watching_eps)], "watching"
        )

        # Plan to watch show
        ptw_show = _make_show("Stranger Things", 2016, imdb="tt4574334")
        ptw_eps = [
            _make_episode(1, season=1, watched_at="2025-03-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-03-02T12:00:00Z"),
            _make_episode(3, season=1, watched_at="2025-03-03T12:00:00Z"),
        ]
        ptw_item = _make_show_item(
            ptw_show, [_make_season(1, ptw_eps)], "plantowatch"
        )

        # Hold show
        hold_show = _make_show("Lost", 2004, imdb="tt0411008")
        hold_eps = [
            _make_episode(1, season=1, watched_at="2025-04-01T12:00:00Z"),
        ]
        hold_item = _make_show_item(
            hold_show, [_make_season(1, hold_eps)], "hold"
        )

        # Dropped show
        dropped_show = _make_show("Dexter", 2006, imdb="tt0773262")
        dropped_eps = [
            _make_episode(1, season=1, watched_at="2025-05-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-05-02T12:00:00Z"),
        ]
        dropped_item = _make_show_item(
            dropped_show, [_make_season(1, dropped_eps)], "dropped"
        )

        all_items = _build_all_items_response(
            shows=[completed_item, watching_item, ptw_item, hold_item, dropped_item]
        )
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        # Only completed (2) + watching (1) = 3 episodes
        assert len(eps) == 3

        # Verify show titles in results
        show_titles = {v[0] for v in eps.values()}
        assert "Breaking Bad" in show_titles
        assert "The Bear" in show_titles
        assert "Stranger Things" not in show_titles
        assert "Lost" not in show_titles
        assert "Dexter" not in show_titles


# ═══════════════════════════════════════════════════════════════════════════════
# MIXED MOVIES + SHOWS in one response
# ═══════════════════════════════════════════════════════════════════════════════


class TestMixedMoviesAndShows:
    """Combined movies and shows across different statuses."""

    @patch("simkl_utils.simkl_request")
    def test_full_mixed_response(self, mock_req):
        movies_list = [
            _make_movie_item(
                _make_movie("Inception", 2010, imdb="tt1375666"),
                "completed", "2025-01-15T10:00:00Z"
            ),
            _make_movie_item(
                _make_movie("Dune Part Two", 2024, imdb="tt15239678"),
                "plantowatch"
            ),
            _make_movie_item(
                _make_movie("Interstellar", 2014, imdb="tt0816692"),
                "watching", "2025-02-01T00:00:00Z"
            ),
            _make_movie_item(
                _make_movie("The Room", 2003, imdb="tt0368226"),
                "dropped"
            ),
        ]

        completed_show = _make_show("Better Call Saul", 2015, imdb="tt3032476")
        completed_eps = [
            _make_episode(1, season=1, watched_at="2025-03-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-03-02T12:00:00Z"),
        ]
        completed_show_item = _make_show_item(
            completed_show, [_make_season(1, completed_eps)], "completed"
        )

        ptw_show = _make_show("Arcane", 2021, imdb="tt11126994")
        ptw_eps = [
            _make_episode(1, season=1, watched_at="2025-04-01T12:00:00Z"),
        ]
        ptw_show_item = _make_show_item(
            ptw_show, [_make_season(1, ptw_eps)], "plantowatch"
        )

        all_items = _build_all_items_response(
            movies=movies_list,
            shows=[completed_show_item, ptw_show_item]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, eps = get_simkl_history(FAKE_HEADERS)

        # Movies: only completed + watching = 2
        assert len(movies) == 2
        assert "imdb://tt1375666" in movies  # completed
        assert "imdb://tt0816692" in movies  # watching
        assert "imdb://tt15239678" not in movies  # plantowatch
        assert "imdb://tt0368226" not in movies  # dropped

        # Episodes: only completed show = 2
        assert len(eps) == 2
        show_titles = {v[0] for v in eps.values()}
        assert "Better Call Saul" in show_titles
        assert "Arcane" not in show_titles


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTION with /sync/history
# ═══════════════════════════════════════════════════════════════════════════════


class TestHistoryAndAllItemsInteraction:
    """Items from /sync/history should still work; /sync/all-items should
    only add items not already seen, and only if they're in watched status."""

    @patch("simkl_utils.simkl_request")
    def test_history_movie_not_overwritten_by_allitems_plantowatch(self, mock_req):
        """If a movie is in /sync/history (watched) AND in /sync/all-items
        as plantowatch, it should remain as watched from history."""
        history_movies = [
            {
                "movie": _make_movie("Inception", 2010, imdb="tt1375666"),
                "watched_at": "2025-01-15T10:00:00Z",
            }
        ]
        # Same movie appears in all-items as plantowatch (e.g. user re-added to PTW)
        all_items = _build_all_items_response(
            movies=[
                _make_movie_item(
                    _make_movie("Inception", 2010, imdb="tt1375666"),
                    "plantowatch"
                )
            ]
        )
        _setup_mock(mock_req, history_movies=history_movies, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        # The movie should still be present from /sync/history
        assert "imdb://tt1375666" in movies
        assert movies["imdb://tt1375666"][2] == "2025-01-15T10:00:00Z"

    @patch("simkl_utils.simkl_request")
    def test_history_movie_not_duplicated_by_completed_allitems(self, mock_req):
        """Movie in both /sync/history and /sync/all-items (completed)
        should only appear once, keeping the history entry."""
        history_movies = [
            {
                "movie": _make_movie("The Dark Knight", 2008, imdb="tt0468569"),
                "watched_at": "2025-01-10T08:00:00Z",
            }
        ]
        all_items = _build_all_items_response(
            movies=[
                _make_movie_item(
                    _make_movie("The Dark Knight", 2008, imdb="tt0468569"),
                    "completed", "2025-01-10T08:00:00Z"
                )
            ]
        )
        _setup_mock(mock_req, history_movies=history_movies, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert len(movies) == 1
        assert "imdb://tt0468569" in movies

    @patch("simkl_utils.simkl_request")
    def test_allitems_adds_completed_movies_not_in_history(self, mock_req):
        """Movies in /sync/all-items (completed) but not in /sync/history
        should be included."""
        all_items = _build_all_items_response(
            movies=[
                _make_movie_item(
                    _make_movie("Parasite", 2019, imdb="tt6751668"),
                    "completed", "2025-06-01T00:00:00Z"
                )
            ]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "imdb://tt6751668" in movies
        assert movies["imdb://tt6751668"][0] == "Parasite"


# ═══════════════════════════════════════════════════════════════════════════════
# ANIME – Shows with anidb IDs
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnimeFiltering:
    """Anime items (which use anidb IDs) must also be filtered."""

    @patch("simkl_utils.simkl_request")
    def test_anime_movie_plantowatch_excluded(self, mock_req):
        movie = _make_movie("Your Name", 2016, anidb=11829)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "plantowatch")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert len(movies) == 0

    @patch("simkl_utils.simkl_request")
    def test_anime_movie_completed_included(self, mock_req):
        movie = _make_movie("Your Name", 2016, anidb=11829)
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-04-01T00:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert "anidb://11829" in movies

    @patch("simkl_utils.simkl_request")
    def test_anime_show_plantowatch_excluded(self, mock_req):
        show = _make_show("Attack on Titan", 2013, anidb=9541)
        episodes = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-01-02T12:00:00Z"),
        ]
        show_item = _make_show_item(show, [_make_season(1, episodes)], "plantowatch")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0

    @patch("simkl_utils.simkl_request")
    def test_anime_show_completed_included(self, mock_req):
        show = _make_show("Death Note", 2006, anidb=4563)
        episodes = [
            _make_episode(1, season=1, watched_at="2025-01-01T12:00:00Z"),
            _make_episode(2, season=1, watched_at="2025-01-02T12:00:00Z"),
        ]
        show_item = _make_show_item(
            show, [_make_season(1, episodes)], "completed"
        )

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Edge cases: empty responses, null data, missing fields."""

    @patch("simkl_utils.simkl_request")
    def test_null_allitems_response(self, mock_req):
        _setup_mock(mock_req, all_items=None)
        movies, eps = get_simkl_history(FAKE_HEADERS)
        assert movies == {}
        assert eps == {}

    @patch("simkl_utils.simkl_request")
    def test_empty_dict_allitems_response(self, mock_req):
        _setup_mock(mock_req, all_items={})
        movies, eps = get_simkl_history(FAKE_HEADERS)
        assert movies == {}
        assert eps == {}

    @patch("simkl_utils.simkl_request")
    def test_allitems_with_empty_movie_list(self, mock_req):
        all_items = _build_all_items_response(movies=[], shows=[])
        _setup_mock(mock_req, all_items=all_items)
        movies, eps = get_simkl_history(FAKE_HEADERS)
        assert movies == {}
        assert eps == {}

    @patch("simkl_utils.simkl_request")
    def test_movie_without_ids_skipped(self, mock_req):
        """A movie with no IDs should be skipped regardless of status."""
        movie = {"title": "No IDs Movie", "year": 2023, "ids": {}}
        all_items = _build_all_items_response(
            movies=[_make_movie_item(movie, "completed", "2025-01-01T00:00:00Z")]
        )
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert len(movies) == 0

    @patch("simkl_utils.simkl_request")
    def test_show_with_no_watched_episodes_skipped(self, mock_req):
        """A completed show where no episodes have watched_at/plays should
        produce no episode entries."""
        show = _make_show("Empty Show", 2020, imdb="tt1111111")
        episodes = [
            {"number": 1, "season": 1},  # no watched_at, no plays
            {"number": 2, "season": 1},
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "completed")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 0

    @patch("simkl_utils.simkl_request")
    def test_episode_with_plays_but_no_watched_at_included(self, mock_req):
        """Episodes with plays > 0 but no watched_at should still be
        included if the show is completed."""
        show = _make_show("Plays Only Show", 2020, imdb="tt2222222")
        episodes = [
            _make_episode(1, season=1, plays=3),
        ]
        season = _make_season(1, episodes)
        show_item = _make_show_item(show, [season], "completed")

        all_items = _build_all_items_response(shows=[show_item])
        _setup_mock(mock_req, all_items=all_items)

        _, eps = get_simkl_history(FAKE_HEADERS)
        assert len(eps) == 1

    @patch("simkl_utils.simkl_request")
    def test_many_plantowatch_movies_all_excluded(self, mock_req):
        """Simulate a large Plan to Watch list — none should appear."""
        movies_list = [
            _make_movie_item(
                _make_movie(f"PTW Movie {i}", 2020 + (i % 5), imdb=f"tt{9000000 + i}"),
                "plantowatch"
            )
            for i in range(50)
        ]
        all_items = _build_all_items_response(movies=movies_list)
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        assert len(movies) == 0

    @patch("simkl_utils.simkl_request")
    def test_large_mixed_list(self, mock_req):
        """Large response with 100 movies across statuses."""
        statuses = ["completed", "watching", "plantowatch", "hold", "dropped"]
        movies_list = [
            _make_movie_item(
                _make_movie(f"Movie {i}", 2020, imdb=f"tt{7000000 + i}"),
                statuses[i % 5],
                "2025-01-01T00:00:00Z" if statuses[i % 5] in ("completed", "watching") else None,
            )
            for i in range(100)
        ]
        all_items = _build_all_items_response(movies=movies_list)
        _setup_mock(mock_req, all_items=all_items)

        movies, _ = get_simkl_history(FAKE_HEADERS)
        # 100 movies, 5 statuses cycling: 0=completed, 1=watching, 2=ptw, 3=hold, 4=dropped
        # completed: indices 0, 5, 10, ... = 20
        # watching: indices 1, 6, 11, ... = 20
        assert len(movies) == 40
