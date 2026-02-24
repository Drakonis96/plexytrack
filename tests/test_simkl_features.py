"""
Tests for all new Simkl features (#1–#12) implemented in simkl_utils.py.

Each feature has its own test class; every test uses mocking so no real API
calls are made and no external dependencies (Plex, network) are required.
"""

import json
import os
import sys
import tempfile
from typing import Any, Dict, Optional
from unittest import mock
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from simkl_utils import (
    # Feature #1 – Incremental sync via /sync/activities
    get_simkl_last_activities,
    has_simkl_category_changed,
    update_saved_activities,
    _load_saved_activities,
    _save_activities,
    ACTIVITIES_FILE,
    # Feature #2 – /sync/all-items
    get_simkl_all_items,
    parse_all_items_response,
    # Feature #3 – Watchlist / plan-to-watch
    add_items_to_simkl_list,
    get_simkl_watchlist,
    sync_plex_watchlist_to_simkl,
    SIMKL_LIST_STATUSES,
    # Feature #4 – Remove from history
    remove_simkl_history,
    # Feature #5 – Remove ratings
    remove_simkl_ratings,
    # Feature #6 – date_from on ratings
    fetch_simkl_ratings_incremental,
    # Feature #7 – Full scrobble lifecycle
    _build_scrobble_payload,
    simkl_scrobble_start,
    simkl_scrobble_pause,
    simkl_scrobble_stop,
    # Feature #8 – Playback progress
    get_simkl_playback_progress,
    delete_simkl_playback_item,
    sync_plex_playback_to_simkl,
    # Feature #9 – Check-in
    simkl_checkin,
    # Feature #10 – Check if watched
    simkl_check_watched,
    # Feature #11 – Anime handling
    update_simkl_anime,
    is_anime_item,
    # Feature #12 – Calendar
    fetch_simkl_calendar,
    get_upcoming_for_watchlist,
    CALENDAR_BASE_URL,
    # Existing helpers
    simkl_movie_key,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

FAKE_HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer fake_token",
    "simkl-api-key": "fake_client_id",
}


def _mock_response(json_data=None, status_code=200, content=b"ok"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.content = content
    resp.raise_for_status.return_value = None
    return resp


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #1 – Incremental sync via /sync/activities
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyncActivities:
    """Tests for get_simkl_last_activities, has_simkl_category_changed,
    update_saved_activities, _load_saved_activities, _save_activities."""

    SAMPLE_ACTIVITIES = {
        "all": "2025-10-12T09:03:45Z",
        "movies": {"all": "2025-10-12T09:03:45Z", "rated_at": "2025-10-11T08:00:00Z"},
        "tv_shows": {"all": "2025-10-10T09:03:45Z", "rated_at": "2025-10-09T08:00:00Z"},
        "anime": {"all": "2025-10-08T09:03:45Z"},
        "settings": {"all": "2025-10-07T09:03:45Z"},
    }

    @patch("simkl_utils.simkl_request")
    def test_get_last_activities_returns_dict(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_ACTIVITIES)
        result = get_simkl_last_activities(FAKE_HEADERS)
        assert isinstance(result, dict)
        assert result["all"] == "2025-10-12T09:03:45Z"
        mock_req.assert_called_once_with("POST", "/sync/activities", FAKE_HEADERS)

    @patch("simkl_utils.simkl_request")
    def test_get_last_activities_includes_categories(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_ACTIVITIES)
        result = get_simkl_last_activities(FAKE_HEADERS)
        assert "movies" in result
        assert "tv_shows" in result
        assert "anime" in result
        assert "settings" in result

    def test_save_and_load_activities(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "simkl_activities.json")
            with patch("simkl_utils.ACTIVITIES_FILE", fpath):
                _save_activities(self.SAMPLE_ACTIVITIES)
                loaded = _load_saved_activities()
                assert loaded["all"] == self.SAMPLE_ACTIVITIES["all"]
                assert loaded["movies"]["rated_at"] == "2025-10-11T08:00:00Z"

    def test_load_activities_returns_empty_when_missing(self):
        with patch("simkl_utils.ACTIVITIES_FILE", "/nonexistent/path.json"):
            result = _load_saved_activities()
            assert result == {}

    def test_has_category_changed_first_run(self):
        with patch("simkl_utils._load_saved_activities", return_value={}):
            changed, saved_ts = has_simkl_category_changed("all")
            assert changed is True
            assert saved_ts is None

    def test_has_category_changed_nested(self):
        with patch("simkl_utils._load_saved_activities", return_value=self.SAMPLE_ACTIVITIES):
            changed, saved_ts = has_simkl_category_changed("movies.rated_at")
            assert changed is True
            assert saved_ts == "2025-10-11T08:00:00Z"

    def test_update_saved_activities(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = os.path.join(tmpdir, "simkl_activities.json")
            with patch("simkl_utils.ACTIVITIES_FILE", fpath):
                update_saved_activities(self.SAMPLE_ACTIVITIES)
                with open(fpath, "r") as f:
                    stored = json.load(f)
                assert stored["all"] == self.SAMPLE_ACTIVITIES["all"]


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #2 – /sync/all-items
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyncAllItems:
    SAMPLE_ALL_ITEMS = {
        "movies": [
            {
                "movie": {
                    "title": "Inception",
                    "year": 2010,
                    "ids": {"imdb": "tt1375666", "tmdb": 27205},
                },
                "last_watched_at": "2025-01-15T10:00:00Z",
            }
        ],
        "shows": [
            {
                "show": {
                    "title": "Breaking Bad",
                    "year": 2008,
                    "ids": {"imdb": "tt0903747", "tvdb": 81189},
                },
                "seasons": [
                    {
                        "number": 1,
                        "episodes": [
                            {"number": 1, "watched_at": "2025-02-01T12:00:00Z"},
                            {"number": 2, "watched_at": "2025-02-02T12:00:00Z"},
                        ],
                    }
                ],
                "last_watched_at": "2025-02-02T12:00:00Z",
            }
        ],
        "anime": [],
    }

    @patch("simkl_utils.simkl_request")
    def test_get_all_items_no_params(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_ALL_ITEMS)
        result = get_simkl_all_items(FAKE_HEADERS)
        assert "movies" in result
        assert "shows" in result
        mock_req.assert_called_once()
        call_args = mock_req.call_args
        assert call_args[0][1] == "/sync/all-items"

    @patch("simkl_utils.simkl_request")
    def test_get_all_items_with_date_from(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_ALL_ITEMS)
        get_simkl_all_items(FAKE_HEADERS, "movies", date_from="2025-01-01T00:00:00Z")
        call_args = mock_req.call_args
        assert call_args[0][1] == "/sync/all-items/movies/"
        assert call_args[1]["params"]["date_from"] == "2025-01-01T00:00:00Z"

    @patch("simkl_utils.simkl_request")
    def test_get_all_items_with_extended(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_ALL_ITEMS)
        get_simkl_all_items(FAKE_HEADERS, extended="full", episode_watched_at=True)
        params = mock_req.call_args[1]["params"]
        assert params["extended"] == "full"
        assert params["episode_watched_at"] == "yes"

    def test_parse_all_items_movies(self):
        movies, episodes = parse_all_items_response(self.SAMPLE_ALL_ITEMS)
        assert len(movies) == 1
        key = "imdb://tt1375666"
        assert key in movies
        assert movies[key][0] == "Inception"
        assert movies[key][1] == 2010

    def test_parse_all_items_episodes(self):
        movies, episodes = parse_all_items_response(self.SAMPLE_ALL_ITEMS)
        assert len(episodes) == 2
        # Episodes should have S01E01, S01E02 codes
        codes = {v[1] for v in episodes.values()}
        assert "S01E01" in codes
        assert "S01E02" in codes

    def test_parse_all_items_empty(self):
        movies, episodes = parse_all_items_response({})
        assert movies == {}
        assert episodes == {}

    @patch("simkl_utils.simkl_request")
    def test_get_all_items_null_response(self, mock_req):
        mock_req.return_value = _mock_response(None)
        result = get_simkl_all_items(FAKE_HEADERS)
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #3 – Watchlist / plan-to-watch sync
# ═══════════════════════════════════════════════════════════════════════════════

class TestWatchlistSync:
    @patch("simkl_utils.simkl_request")
    def test_add_items_plantowatch(self, mock_req):
        mock_req.return_value = _mock_response({"added": {"movies": 1}})
        movies = [{"title": "Dune", "year": 2021, "ids": {"tmdb": 438631}}]
        result = add_items_to_simkl_list(FAKE_HEADERS, movies=movies, target_list="plantowatch")
        call_payload = mock_req.call_args[1]["json"]
        assert call_payload["movies"][0]["to"] == "plantowatch"
        assert result["added"]["movies"] == 1

    @patch("simkl_utils.simkl_request")
    def test_add_items_watching(self, mock_req):
        mock_req.return_value = _mock_response({"added": {"shows": 1}})
        shows = [{"title": "The Bear", "ids": {"imdb": "tt14452776"}}]
        result = add_items_to_simkl_list(FAKE_HEADERS, shows=shows, target_list="watching")
        call_payload = mock_req.call_args[1]["json"]
        assert call_payload["shows"][0]["to"] == "watching"

    def test_add_items_invalid_list_raises(self):
        with pytest.raises(ValueError, match="Invalid target list"):
            add_items_to_simkl_list(FAKE_HEADERS, movies=[], target_list="invalid_status")

    @patch("simkl_utils.simkl_request")
    def test_add_items_empty_payload(self, mock_req):
        result = add_items_to_simkl_list(FAKE_HEADERS, target_list="plantowatch")
        assert result == {}
        mock_req.assert_not_called()

    def test_simkl_list_statuses_constant(self):
        assert "plantowatch" in SIMKL_LIST_STATUSES
        assert "watching" in SIMKL_LIST_STATUSES
        assert "completed" in SIMKL_LIST_STATUSES
        assert "hold" in SIMKL_LIST_STATUSES
        assert "dropped" in SIMKL_LIST_STATUSES

    @patch("simkl_utils.simkl_request")
    def test_get_watchlist(self, mock_req):
        mock_req.return_value = _mock_response({"movies": [], "shows": []})
        result = get_simkl_watchlist(FAKE_HEADERS, media_type="movies")
        call_args = mock_req.call_args
        assert "/sync/all-items/movies/" in call_args[0][1]

    @patch("simkl_utils.add_items_to_simkl_list")
    @patch("simkl_utils.guid_to_ids", return_value={"tmdb": 123})
    @patch("simkl_utils.best_guid", return_value="tmdb://123")
    def test_sync_plex_watchlist(self, mock_guid, mock_ids, mock_add):
        mock_add.return_value = {}
        plex = MagicMock()
        item1 = MagicMock()
        item1.title = "Test Movie"
        item1.type = "movie"
        item1.year = 2024
        item2 = MagicMock()
        item2.title = "Test Show"
        item2.type = "show"
        item2.year = 2023
        plex.watchlist.return_value = [item1, item2]
        count = sync_plex_watchlist_to_simkl(plex, FAKE_HEADERS)
        assert count == 2
        mock_add.assert_called_once()

    @patch("simkl_utils.add_items_to_simkl_list")
    def test_sync_plex_watchlist_empty(self, mock_add):
        plex = MagicMock()
        plex.watchlist.return_value = []
        count = sync_plex_watchlist_to_simkl(plex, FAKE_HEADERS)
        assert count == 0
        mock_add.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #4 – Remove from history
# ═══════════════════════════════════════════════════════════════════════════════

class TestRemoveHistory:
    @patch("simkl_utils.simkl_request")
    def test_remove_movies(self, mock_req):
        mock_req.return_value = _mock_response({"deleted": {"movies": 1}})
        movies = [{"ids": {"imdb": "tt1375666"}}]
        result = remove_simkl_history(FAKE_HEADERS, movies=movies)
        mock_req.assert_called_once()
        assert mock_req.call_args[0][0] == "DELETE"
        assert mock_req.call_args[0][1] == "/sync/history"
        assert result["deleted"]["movies"] == 1

    @patch("simkl_utils.simkl_request")
    def test_remove_shows(self, mock_req):
        mock_req.return_value = _mock_response({"deleted": {"shows": 1}})
        shows = [{"ids": {"tvdb": 81189}}]
        result = remove_simkl_history(FAKE_HEADERS, shows=shows)
        payload = mock_req.call_args[1]["json"]
        assert "shows" in payload
        assert len(payload["shows"]) == 1

    def test_remove_empty(self):
        result = remove_simkl_history(FAKE_HEADERS)
        assert result == {}

    @patch("simkl_utils.simkl_request")
    def test_remove_movies_and_shows(self, mock_req):
        mock_req.return_value = _mock_response({"deleted": {"movies": 2, "shows": 1}})
        movies = [{"ids": {"tmdb": 1}}, {"ids": {"tmdb": 2}}]
        shows = [{"ids": {"tvdb": 100}}]
        result = remove_simkl_history(FAKE_HEADERS, movies=movies, shows=shows)
        payload = mock_req.call_args[1]["json"]
        assert len(payload["movies"]) == 2
        assert len(payload["shows"]) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #5 – Remove ratings
# ═══════════════════════════════════════════════════════════════════════════════

class TestRemoveRatings:
    @patch("simkl_utils.simkl_request")
    def test_remove_movie_ratings(self, mock_req):
        mock_req.return_value = _mock_response({"deleted": {"movies": 1}})
        movies = [{"ids": {"imdb": "tt1375666"}}]
        result = remove_simkl_ratings(FAKE_HEADERS, movies=movies)
        assert mock_req.call_args[0][0] == "DELETE"
        assert mock_req.call_args[0][1] == "/sync/ratings"
        assert result["deleted"]["movies"] == 1

    @patch("simkl_utils.simkl_request")
    def test_remove_show_ratings(self, mock_req):
        mock_req.return_value = _mock_response({"deleted": {"shows": 2}})
        shows = [{"ids": {"tvdb": 81189}}, {"ids": {"tvdb": 99999}}]
        result = remove_simkl_ratings(FAKE_HEADERS, shows=shows)
        payload = mock_req.call_args[1]["json"]
        assert len(payload["shows"]) == 2

    def test_remove_ratings_empty(self):
        result = remove_simkl_ratings(FAKE_HEADERS)
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #6 – date_from on ratings
# ═══════════════════════════════════════════════════════════════════════════════

class TestRatingsDateFrom:
    SAMPLE_RATINGS = {
        "movies": [
            {"ids": {"imdb": "tt1375666"}, "rating": 9, "rated_at": "2025-10-12T09:00:00Z"}
        ],
        "shows": [
            {"ids": {"tvdb": 81189}, "rating": 10, "rated_at": "2025-10-11T08:00:00Z"}
        ],
    }

    @patch("simkl_utils.simkl_request")
    def test_fetch_incremental_with_date(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_RATINGS)
        items = fetch_simkl_ratings_incremental(FAKE_HEADERS, date_from="2025-10-01T00:00:00Z")
        params = mock_req.call_args[1]["params"]
        assert params["date_from"] == "2025-10-01T00:00:00Z"
        assert len(items) == 2
        assert items[0]["rated_at"] == "2025-10-12T09:00:00Z"

    @patch("simkl_utils.simkl_request")
    def test_fetch_incremental_without_date(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_RATINGS)
        items = fetch_simkl_ratings_incremental(FAKE_HEADERS)
        params = mock_req.call_args[1]["params"]
        assert "date_from" not in params
        assert len(items) == 2

    @patch("simkl_utils.simkl_request")
    def test_fetch_incremental_contains_rating_info(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_RATINGS)
        items = fetch_simkl_ratings_incremental(FAKE_HEADERS)
        movie_item = next(i for i in items if i["type"] == "movie")
        assert movie_item["rating"] == 9
        assert movie_item["ids"]["imdb"] == "tt1375666"

    @patch("simkl_utils.simkl_request", side_effect=Exception("network error"))
    def test_fetch_incremental_error(self, mock_req):
        items = fetch_simkl_ratings_incremental(FAKE_HEADERS)
        assert items == []


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #7 – Full scrobble lifecycle (start / pause / stop)
# ═══════════════════════════════════════════════════════════════════════════════

class TestScrobbleLifecycle:
    MOVIE_DATA = {
        "type": "movie",
        "title": "Inception",
        "year": 2010,
        "ids": {"imdb": "tt1375666"},
    }
    EPISODE_DATA = {
        "type": "episode",
        "show_title": "Breaking Bad",
        "show_year": 2008,
        "show_ids": {"tvdb": 81189},
        "season": 1,
        "episode": 1,
        "episode_ids": {"tvdb": 349232},
    }

    def test_build_payload_movie(self):
        payload = _build_scrobble_payload(self.MOVIE_DATA, 25.5)
        assert payload["progress"] == 25.5
        assert payload["movie"]["title"] == "Inception"
        assert payload["movie"]["ids"]["imdb"] == "tt1375666"
        assert "episode" not in payload

    def test_build_payload_episode(self):
        payload = _build_scrobble_payload(self.EPISODE_DATA, 50.0)
        assert payload["progress"] == 50.0
        assert payload["episode"]["season"] == 1
        assert payload["episode"]["number"] == 1
        assert payload["show"]["title"] == "Breaking Bad"

    @patch("simkl_utils.simkl_request")
    def test_scrobble_start(self, mock_req):
        mock_req.return_value = _mock_response({"result": "success"})
        result = simkl_scrobble_start(FAKE_HEADERS, self.MOVIE_DATA, 0.0)
        assert mock_req.call_args[0][1] == "/scrobble/start"
        payload = mock_req.call_args[1]["json"]
        assert payload["progress"] == 0.0

    @patch("simkl_utils.simkl_request")
    def test_scrobble_pause(self, mock_req):
        mock_req.return_value = _mock_response({"result": "success"})
        result = simkl_scrobble_pause(FAKE_HEADERS, self.MOVIE_DATA, 45.0)
        assert mock_req.call_args[0][1] == "/scrobble/pause"
        payload = mock_req.call_args[1]["json"]
        assert payload["progress"] == 45.0

    @patch("simkl_utils.simkl_request")
    def test_scrobble_stop_marks_watched(self, mock_req):
        mock_req.return_value = _mock_response({"result": "success"})
        result = simkl_scrobble_stop(FAKE_HEADERS, self.MOVIE_DATA, 85.0)
        assert mock_req.call_args[0][1] == "/scrobble/stop"
        payload = mock_req.call_args[1]["json"]
        assert payload["progress"] == 85.0

    @patch("simkl_utils.simkl_request")
    def test_scrobble_stop_default_100(self, mock_req):
        mock_req.return_value = _mock_response({})
        simkl_scrobble_stop(FAKE_HEADERS, self.MOVIE_DATA)
        payload = mock_req.call_args[1]["json"]
        assert payload["progress"] == 100.0

    @patch("simkl_utils.simkl_request")
    def test_scrobble_episode(self, mock_req):
        mock_req.return_value = _mock_response({})
        simkl_scrobble_start(FAKE_HEADERS, self.EPISODE_DATA, 5.0)
        payload = mock_req.call_args[1]["json"]
        assert "episode" in payload
        assert payload["episode"]["season"] == 1
        assert payload["show"]["ids"]["tvdb"] == 81189


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #8 – Playback progress sync
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlaybackProgress:
    SAMPLE_PLAYBACK = [
        {
            "movie": {"title": "Dune", "ids": {"simkl": 12345}},
            "progress": 45.2,
            "paused_at": "2025-10-12T09:00:00Z",
        },
        {
            "show": {"title": "Lost", "ids": {"simkl": 67890}},
            "episode": {"season": 2, "number": 5},
            "progress": 22.0,
            "paused_at": "2025-10-11T08:00:00Z",
        },
    ]

    @patch("simkl_utils.simkl_request")
    def test_get_playback_progress(self, mock_req):
        mock_req.return_value = _mock_response(self.SAMPLE_PLAYBACK)
        result = get_simkl_playback_progress(FAKE_HEADERS)
        assert len(result) == 2
        assert result[0]["movie"]["title"] == "Dune"
        assert result[0]["progress"] == 45.2

    @patch("simkl_utils.simkl_request", side_effect=Exception("connection error"))
    def test_get_playback_progress_error(self, mock_req):
        result = get_simkl_playback_progress(FAKE_HEADERS)
        assert result == []

    @patch("simkl_utils.simkl_request")
    def test_delete_playback_item(self, mock_req):
        mock_req.return_value = _mock_response(None, 204)
        result = delete_simkl_playback_item(FAKE_HEADERS, 12345)
        assert result is True
        assert mock_req.call_args[0][0] == "DELETE"
        assert "/sync/playback/12345" in mock_req.call_args[0][1]

    @patch("simkl_utils.simkl_request", side_effect=Exception("error"))
    def test_delete_playback_item_error(self, mock_req):
        result = delete_simkl_playback_item(FAKE_HEADERS, 99999)
        assert result is False

    @patch("simkl_utils.simkl_scrobble_pause")
    @patch("simkl_utils.guid_to_ids", return_value={"tmdb": 438631})
    @patch("simkl_utils.best_guid", return_value="tmdb://438631")
    def test_sync_plex_playback(self, mock_guid, mock_ids, mock_pause):
        plex = MagicMock()
        item = MagicMock()
        item.type = "movie"
        item.title = "Dune"
        item.year = 2021
        item.viewOffset = 3600000   # 60 min
        item.duration = 9000000     # 150 min
        plex.library.onDeck.return_value = [item]
        count = sync_plex_playback_to_simkl(plex, FAKE_HEADERS)
        assert count == 1
        mock_pause.assert_called_once()
        # Progress should be ~40%
        progress_arg = mock_pause.call_args[0][2]
        assert 39.0 < progress_arg < 41.0

    def test_sync_plex_playback_empty_deck(self):
        plex = MagicMock()
        plex.library.onDeck.return_value = []
        count = sync_plex_playback_to_simkl(plex, FAKE_HEADERS)
        assert count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #9 – Check-in
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckin:
    MOVIE_DATA = {
        "type": "movie",
        "title": "Inception",
        "year": 2010,
        "ids": {"imdb": "tt1375666"},
    }
    EPISODE_DATA = {
        "type": "episode",
        "show_title": "Lost",
        "show_ids": {"tvdb": 73739},
        "season": 1,
        "episode": 1,
        "episode_ids": {},
    }

    @patch("simkl_utils.simkl_request")
    def test_checkin_movie(self, mock_req):
        mock_req.return_value = _mock_response({"result": "success"})
        result = simkl_checkin(FAKE_HEADERS, self.MOVIE_DATA)
        assert mock_req.call_args[0][0] == "POST"
        assert mock_req.call_args[0][1] == "/checkin"
        payload = mock_req.call_args[1]["json"]
        assert "movie" in payload
        assert payload["movie"]["title"] == "Inception"

    @patch("simkl_utils.simkl_request")
    def test_checkin_episode(self, mock_req):
        mock_req.return_value = _mock_response({"result": "success"})
        result = simkl_checkin(FAKE_HEADERS, self.EPISODE_DATA)
        payload = mock_req.call_args[1]["json"]
        assert "episode" in payload
        assert "show" in payload
        assert payload["episode"]["season"] == 1

    @patch("simkl_utils.simkl_request")
    def test_checkin_conflict_409(self, mock_req):
        error_resp = MagicMock()
        error_resp.status_code = 409
        error_resp.content = b'{"expires_at": "2025-10-12T10:00:00Z"}'
        error_resp.json.return_value = {"expires_at": "2025-10-12T10:00:00Z"}
        import requests as req_mod
        http_error = req_mod.exceptions.HTTPError(response=error_resp)
        mock_req.side_effect = http_error
        result = simkl_checkin(FAKE_HEADERS, self.MOVIE_DATA)
        assert result["expires_at"] == "2025-10-12T10:00:00Z"


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #10 – Check if watched
# ═══════════════════════════════════════════════════════════════════════════════

class TestCheckWatched:
    @patch("simkl_utils.simkl_request")
    def test_check_single_item(self, mock_req):
        mock_req.return_value = _mock_response([
            {"result": True, "list": "completed", "last_watched_at": "2025-10-12T09:00:00Z"}
        ])
        items = [{"imdb": "tt1375666"}]
        result = simkl_check_watched(FAKE_HEADERS, items)
        assert result[0]["result"] is True
        assert result[0]["list"] == "completed"
        assert mock_req.call_args[0][0] == "POST"
        assert mock_req.call_args[0][1] == "/sync/check"

    @patch("simkl_utils.simkl_request")
    def test_check_multiple_items(self, mock_req):
        mock_req.return_value = _mock_response([
            {"result": True, "list": "completed"},
            {"result": False},
            {"result": "not_found"},
        ])
        items = [{"imdb": "tt1375666"}, {"tmdb": 99999}, {"title": "Fake Movie"}]
        result = simkl_check_watched(FAKE_HEADERS, items)
        assert len(result) == 3
        assert result[2]["result"] == "not_found"

    @patch("simkl_utils.simkl_request")
    def test_check_with_extended_counters(self, mock_req):
        mock_req.return_value = _mock_response([
            {
                "result": True,
                "list": "watching",
                "episodes_total": 10,
                "episodes_watched": 6,
            }
        ])
        result = simkl_check_watched(FAKE_HEADERS, [{"tvdb": 81189}], extended="counters")
        params = mock_req.call_args[1]["params"]
        assert params["extended"] == "counters"
        assert result[0]["episodes_watched"] == 6

    @patch("simkl_utils.simkl_request")
    def test_check_watched_empty_response(self, mock_req):
        mock_req.return_value = _mock_response([], content=b"[]")
        result = simkl_check_watched(FAKE_HEADERS, [])
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #11 – Anime handling
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnimeHandling:
    @patch("simkl_utils.simkl_request")
    def test_update_anime_with_tvdb_seasons(self, mock_req):
        mock_req.return_value = _mock_response({"added": {"shows": 1}})
        anime = [{
            "title": "Attack on Titan",
            "year": 2013,
            "ids": {"mal": 16498, "tvdb": 267440},
            "seasons": [{"number": 1, "episodes": [{"number": 1}, {"number": 2}]}],
        }]
        result = update_simkl_anime(FAKE_HEADERS, anime, use_tvdb_anime_seasons=True)
        payload = mock_req.call_args[1]["json"]
        assert payload["shows"][0]["use_tvdb_anime_seasons"] is True
        assert payload["shows"][0]["title"] == "Attack on Titan"

    @patch("simkl_utils.simkl_request")
    def test_update_anime_without_tvdb_flag(self, mock_req):
        mock_req.return_value = _mock_response({})
        anime = [{"title": "Naruto", "ids": {"mal": 20}}]
        update_simkl_anime(FAKE_HEADERS, anime, use_tvdb_anime_seasons=False)
        payload = mock_req.call_args[1]["json"]
        assert "use_tvdb_anime_seasons" not in payload["shows"][0]

    @patch("simkl_utils.simkl_request")
    def test_update_anime_empty(self, mock_req):
        result = update_simkl_anime(FAKE_HEADERS, [])
        assert result == {}
        mock_req.assert_not_called()

    @patch("simkl_utils.simkl_request")
    def test_update_anime_with_status(self, mock_req):
        mock_req.return_value = _mock_response({})
        anime = [{"title": "One Piece", "ids": {"mal": 21}, "status": "watching"}]
        update_simkl_anime(FAKE_HEADERS, anime)
        payload = mock_req.call_args[1]["json"]
        assert payload["shows"][0]["status"] == "watching"

    def test_is_anime_with_mal_id(self):
        assert is_anime_item({"ids": {"mal": 16498}}) is True

    def test_is_anime_with_anidb_id(self):
        assert is_anime_item({"ids": {"anidb": 9541}}) is True

    def test_is_anime_with_anime_type(self):
        assert is_anime_item({"anime_type": "tv"}) is True

    def test_is_not_anime_regular_show(self):
        assert is_anime_item({"ids": {"imdb": "tt0903747", "tvdb": 81189}}) is False

    def test_is_not_anime_empty(self):
        assert is_anime_item({}) is False


# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE #12 – Calendar integration
# ═══════════════════════════════════════════════════════════════════════════════

class TestCalendar:
    SAMPLE_CALENDAR = [
        {
            "title": "The Last of Us",
            "ids": {"simkl": 1234, "tvdb": 392256},
            "date": "2025-12-01",
            "episode": {"season": 2, "number": 5},
        },
        {
            "title": "House of the Dragon",
            "ids": {"simkl": 5678, "tvdb": 371572},
            "date": "2025-12-02",
            "episode": {"season": 3, "number": 1},
        },
    ]

    @patch("simkl_utils.requests.get")
    def test_fetch_calendar_tv(self, mock_get):
        mock_get.return_value = _mock_response(self.SAMPLE_CALENDAR)
        result = fetch_simkl_calendar("tv")
        assert len(result) == 2
        assert f"{CALENDAR_BASE_URL}/tv.json" in mock_get.call_args[0][0]

    @patch("simkl_utils.requests.get")
    def test_fetch_calendar_anime(self, mock_get):
        mock_get.return_value = _mock_response([])
        result = fetch_simkl_calendar("anime")
        assert result == []
        assert "anime.json" in mock_get.call_args[0][0]

    @patch("simkl_utils.requests.get")
    def test_fetch_calendar_monthly(self, mock_get):
        mock_get.return_value = _mock_response(self.SAMPLE_CALENDAR)
        result = fetch_simkl_calendar("tv", year=2025, month=12)
        url = mock_get.call_args[0][0]
        assert "/2025/12/tv.json" in url

    def test_fetch_calendar_invalid_type(self):
        with pytest.raises(ValueError, match="Invalid calendar type"):
            fetch_simkl_calendar("invalid_type")

    @patch("simkl_utils.requests.get", side_effect=Exception("network error"))
    def test_fetch_calendar_error(self, mock_get):
        result = fetch_simkl_calendar("tv")
        assert result == []

    @patch("simkl_utils.get_simkl_all_items")
    @patch("simkl_utils.fetch_simkl_calendar")
    def test_get_upcoming_for_watchlist(self, mock_cal, mock_items):
        mock_cal.return_value = self.SAMPLE_CALENDAR
        mock_items.return_value = {
            "shows": [
                {"show": {"ids": {"simkl": 1234}}},
            ],
            "anime": [],
            "movies": [],
        }
        result = get_upcoming_for_watchlist(FAKE_HEADERS, "tv")
        assert len(result) == 1
        assert result[0]["ids"]["simkl"] == 1234

    @patch("simkl_utils.get_simkl_all_items")
    @patch("simkl_utils.fetch_simkl_calendar")
    def test_get_upcoming_no_matches(self, mock_cal, mock_items):
        mock_cal.return_value = self.SAMPLE_CALENDAR
        mock_items.return_value = {"shows": [], "anime": [], "movies": []}
        result = get_upcoming_for_watchlist(FAKE_HEADERS, "tv")
        assert result == []

    @patch("simkl_utils.fetch_simkl_calendar", return_value=[])
    def test_get_upcoming_empty_calendar(self, mock_cal):
        result = get_upcoming_for_watchlist(FAKE_HEADERS, "tv")
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION – Webhook helpers (app.py)
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookHelpers:
    """Test the webhook helper functions added to app.py."""

    def test_extract_movie_from_webhook(self):
        sys.path.insert(0, PROJECT_ROOT)
        # Dynamically import to avoid full app bootstrap
        import importlib
        import types

        # Load _extract_simkl_item_from_webhook from app module source
        source_path = os.path.join(PROJECT_ROOT, "app.py")
        with open(source_path, "r") as f:
            source = f.read()

        # Extract the function by parsing the source
        func_start = source.find("def _extract_simkl_item_from_webhook(")
        func_end = source.find("\ndef _calc_webhook_progress(")
        func_source = source[func_start:func_end]

        # Also get _calc_webhook_progress
        calc_start = source.find("def _calc_webhook_progress(")
        calc_end = source.find("\n\n@app.route(\"/webhook\"")
        calc_source = source[calc_start:calc_end]

        ns = {"Optional": Optional, "Dict": dict, "Any": object}
        exec(func_source, ns)
        exec(calc_source, ns)

        extract_fn = ns["_extract_simkl_item_from_webhook"]
        calc_fn = ns["_calc_webhook_progress"]

        # Test movie extraction
        metadata = {
            "type": "movie",
            "title": "Inception",
            "year": 2010,
            "Guid": [
                {"id": "imdb://tt1375666"},
                {"id": "tmdb://27205"},
            ],
        }
        result = extract_fn(metadata)
        assert result["type"] == "movie"
        assert result["title"] == "Inception"
        assert result["ids"]["imdb"] == "tt1375666"
        assert result["ids"]["tmdb"] == 27205

    def test_extract_episode_from_webhook(self):
        source_path = os.path.join(PROJECT_ROOT, "app.py")
        with open(source_path, "r") as f:
            source = f.read()
        func_start = source.find("def _extract_simkl_item_from_webhook(")
        func_end = source.find("\ndef _calc_webhook_progress(")
        func_source = source[func_start:func_end]
        ns = {"Optional": Optional, "Dict": dict, "Any": object}
        exec(func_source, ns)
        extract_fn = ns["_extract_simkl_item_from_webhook"]

        metadata = {
            "type": "episode",
            "grandparentTitle": "Breaking Bad",
            "parentIndex": 3,
            "index": 7,
            "Guid": [{"id": "tvdb://81189"}],
        }
        result = extract_fn(metadata)
        assert result["type"] == "episode"
        assert result["show_title"] == "Breaking Bad"
        assert result["season"] == 3
        assert result["episode"] == 7

    def test_extract_none_metadata(self):
        source_path = os.path.join(PROJECT_ROOT, "app.py")
        with open(source_path, "r") as f:
            source = f.read()
        func_start = source.find("def _extract_simkl_item_from_webhook(")
        func_end = source.find("\ndef _calc_webhook_progress(")
        func_source = source[func_start:func_end]
        ns = {"Optional": Optional, "Dict": dict, "Any": object}
        exec(func_source, ns)
        assert ns["_extract_simkl_item_from_webhook"](None) is None
        assert ns["_extract_simkl_item_from_webhook"]({}) is None

    def test_calc_webhook_progress(self):
        source_path = os.path.join(PROJECT_ROOT, "app.py")
        with open(source_path, "r") as f:
            source = f.read()
        calc_start = source.find("def _calc_webhook_progress(")
        calc_end = source.find("\n\n@app.route(\"/webhook\"")
        calc_source = source[calc_start:calc_end]
        ns = {}
        exec(calc_source, ns)
        calc_fn = ns["_calc_webhook_progress"]

        # 60% progress
        payload = {"Metadata": {"viewOffset": 60000, "duration": 100000}}
        assert calc_fn(payload) == 60.0

        # Zero duration safety
        payload_zero = {"Metadata": {"viewOffset": 0, "duration": 0}}
        assert calc_fn(payload_zero) == 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# EDGE CASES & REGRESSION
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Miscellaneous edge case tests that span multiple features."""

    def test_simkl_movie_key_all_id_types(self):
        assert simkl_movie_key({"ids": {"imdb": "tt123"}}) == "imdb://tt123"
        assert simkl_movie_key({"ids": {"tmdb": 456}}) == "tmdb://456"
        assert simkl_movie_key({"ids": {"tvdb": 789}}) == "tvdb://789"
        assert simkl_movie_key({"ids": {"anidb": 111}}) == "anidb://111"
        assert simkl_movie_key({"ids": {}}) is None
        assert simkl_movie_key({}) is None

    @patch("simkl_utils.simkl_request")
    def test_add_to_all_valid_lists(self, mock_req):
        mock_req.return_value = _mock_response({})
        movies = [{"title": "Test", "ids": {"tmdb": 1}}]
        for status in SIMKL_LIST_STATUSES:
            add_items_to_simkl_list(FAKE_HEADERS, movies=movies, target_list=status)
            payload = mock_req.call_args[1]["json"]
            assert payload["movies"][0]["to"] == status

    @patch("simkl_utils.simkl_request")
    def test_all_items_with_anime_block(self, mock_req):
        data = {
            "movies": [],
            "shows": [],
            "anime": [
                {
                    "show": {
                        "title": "Attack on Titan",
                        "ids": {"mal": 16498, "tvdb": 267440, "imdb": "tt2560140"},
                    },
                    "seasons": [
                        {
                            "number": 1,
                            "episodes": [
                                {"number": 1, "watched_at": "2025-01-01T00:00:00Z"},
                            ],
                        }
                    ],
                }
            ],
        }
        movies, episodes = parse_all_items_response(data)
        assert len(movies) == 0
        assert len(episodes) == 1
        key = list(episodes.keys())[0]
        assert episodes[key][0] == "Attack on Titan"

    @patch("simkl_utils.simkl_request")
    def test_scrobble_start_pause_stop_sequence(self, mock_req):
        """Simulate a full playback cycle: start → pause → stop."""
        mock_req.return_value = _mock_response({})
        item = {
            "type": "movie",
            "title": "Test Movie",
            "year": 2025,
            "ids": {"tmdb": 999},
        }
        simkl_scrobble_start(FAKE_HEADERS, item, 0.0)
        assert mock_req.call_args[0][1] == "/scrobble/start"

        simkl_scrobble_pause(FAKE_HEADERS, item, 42.5)
        assert mock_req.call_args[0][1] == "/scrobble/pause"

        simkl_scrobble_stop(FAKE_HEADERS, item, 95.0)
        assert mock_req.call_args[0][1] == "/scrobble/stop"

        assert mock_req.call_count == 3
