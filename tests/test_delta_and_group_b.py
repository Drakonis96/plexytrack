"""Tests for delta sync (Trakt/Simkl) and the "Group B" additive features.

Covered here (all mocked, no network / Plex required):

Delta sync
    - trakt_utils.get_trakt_last_activities / should_sync_category /
      load_trakt_activities / save_trakt_activities
    - simkl_utils.get_simkl_last_activities / _save_activities /
      _load_saved_activities / update_saved_activities / has_simkl_category_changed

Group B
    #9  Trakt collection of shows/episodes + metadata + import_trakt_collection
    #10 Trakt watchlist ordering + per-item notes
    #11 Trakt personal lists -> Plex
    #12 Simkl hold/dropped statuses via all-items helpers
"""

import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Ensure project root importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ═══════════════════════════════════════════════════════════════════════════
# Trakt – delta sync persistence
# ═══════════════════════════════════════════════════════════════════════════

class TestTraktActivitiesPersistence:
    SAMPLE = {"movies": {"rated_at": "2025-06-01T00:00:00Z", "collected_at": "2025-06-02T00:00:00Z"}}

    def test_save_and_load_roundtrip(self):
        import trakt_utils
        with tempfile.TemporaryDirectory() as tmp:
            fpath = os.path.join(tmp, "trakt_activities.json")
            with patch("trakt_utils.ACTIVITIES_FILE", fpath):
                trakt_utils.save_trakt_activities(self.SAMPLE)
                loaded = trakt_utils.load_trakt_activities()
        assert loaded == self.SAMPLE

    def test_load_missing_returns_empty(self):
        import trakt_utils
        with patch("trakt_utils.ACTIVITIES_FILE", "/nonexistent/x.json"):
            assert trakt_utils.load_trakt_activities() == {}

    def test_save_ignores_non_dict(self):
        import trakt_utils
        with tempfile.TemporaryDirectory() as tmp:
            fpath = os.path.join(tmp, "trakt_activities.json")
            with patch("trakt_utils.ACTIVITIES_FILE", fpath):
                trakt_utils.save_trakt_activities(None)  # must not raise
                assert not os.path.exists(fpath)


# ═══════════════════════════════════════════════════════════════════════════
# Trakt – #9 collection of shows/episodes + metadata
# ═══════════════════════════════════════════════════════════════════════════

class TestSyncCollectionShows:
    def test_shows_payload_built(self, monkeypatch):
        from trakt_utils import sync_collection

        ep1 = MagicMock(); ep1.seasonNumber = 1; ep1.index = 1
        ep2 = MagicMock(); ep2.seasonNumber = 1; ep2.index = 2
        ep3 = MagicMock(); ep3.seasonNumber = 2; ep3.index = 1

        show = MagicMock()
        show.title = "Breaking Bad"
        show.year = 2008
        show.episodes.return_value = [ep1, ep2, ep3]

        section = MagicMock()
        section.type = "show"
        section.all.return_value = [show]

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        posted = []

        def fake_request(method, path, headers, **kw):
            if method == "POST":
                posted.append(kw.get("json", {}))
            return SimpleNamespace(status_code=200, json=lambda: [])

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "tvdb://81189")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"tvdb": 81189})
        monkeypatch.setattr("trakt_utils.normalize_year", lambda y: y)

        sync_collection(plex, {})

        assert len(posted) == 1
        assert "shows" in posted[0]
        shows = posted[0]["shows"]
        assert len(shows) == 1
        seasons = {s["number"]: s for s in shows[0]["seasons"]}
        assert set(seasons) == {1, 2}
        assert len(seasons[1]["episodes"]) == 2
        assert len(seasons[2]["episodes"]) == 1

    def test_include_shows_false_skips_shows(self, monkeypatch):
        from trakt_utils import sync_collection

        show = MagicMock()
        show.episodes.return_value = [MagicMock(seasonNumber=1, index=1)]
        section = MagicMock()
        section.type = "show"
        section.all.return_value = [show]
        plex = MagicMock()
        plex.library.sections.return_value = [section]

        posted = []
        monkeypatch.setattr(
            "trakt_utils.trakt_request",
            lambda method, path, headers, **kw: posted.append(method) or SimpleNamespace(json=lambda: []),
        )
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "tvdb://1")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"tvdb": 1})

        sync_collection(plex, {}, include_shows=False)
        assert "POST" not in posted  # nothing to send

    def test_metadata_extraction(self):
        from trakt_utils import _extract_collection_metadata

        media = MagicMock()
        media.videoResolution = "4k"
        media.audioCodec = "dts"
        media.audioChannels = 6
        media.DOVIPresent = True
        item = MagicMock()
        item.media = [media]

        meta = _extract_collection_metadata(item)
        assert meta["resolution"] == "uhd_4k"
        assert meta["audio"] == "dts"
        assert meta["audio_channels"] == "5.1"
        assert meta["hdr"] == "dolby_vision"

    def test_metadata_unknown_codec_omitted(self):
        from trakt_utils import _extract_collection_metadata

        media = MagicMock()
        media.videoResolution = "totally-unknown"
        media.audioCodec = "weird"
        media.audioChannels = 99
        media.DOVIPresent = False
        item = MagicMock()
        item.media = [media]

        assert _extract_collection_metadata(item) == {}


# ═══════════════════════════════════════════════════════════════════════════
# Trakt – #10 watchlist ordering + notes
# ═══════════════════════════════════════════════════════════════════════════

class TestTraktWatchlistExtras:
    def test_get_watchlist_with_sort(self, monkeypatch):
        from trakt_utils import get_trakt_watchlist
        seen = {}

        def fake_request(method, path, headers, **kw):
            seen["path"] = path
            seen["params"] = kw.get("params")
            return SimpleNamespace(json=lambda: [{"movie": {}}])

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        get_trakt_watchlist({}, "movies", sort_by="rank", sort_how="desc")
        # Official API sends sort via query params, not URL path segments.
        assert seen["path"] == "/sync/watchlist/movies"
        assert seen["params"] == {"sort_by": "rank", "sort_how": "desc"}

    def test_get_watchlist_default_path(self, monkeypatch):
        from trakt_utils import get_trakt_watchlist
        seen = {}
        monkeypatch.setattr(
            "trakt_utils.trakt_request",
            lambda m, p, h, **kw: seen.update(path=p, params=kw.get("params")) or SimpleNamespace(json=lambda: []),
        )
        get_trakt_watchlist({}, "shows")
        assert seen["path"] == "/sync/watchlist/shows"
        assert seen["params"] == {}

    def test_add_watchlist_with_notes(self, monkeypatch):
        from trakt_utils import add_to_trakt_watchlist
        captured = {}

        def fake_request(method, path, headers, **kw):
            captured["json"] = kw.get("json")
            return SimpleNamespace(json=lambda: {"added": {"movies": 1}})

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        res = add_to_trakt_watchlist({}, movies=[{"ids": {"imdb": "tt1"}}], notes="watch soon")
        assert res == {"added": {"movies": 1}}
        assert captured["json"]["movies"][0]["notes"] == "watch soon"

    def test_add_watchlist_empty_returns_none(self, monkeypatch):
        from trakt_utils import add_to_trakt_watchlist
        called = []
        monkeypatch.setattr("trakt_utils.trakt_request", lambda *a, **k: called.append(1))
        assert add_to_trakt_watchlist({}) is None
        assert not called


# ═══════════════════════════════════════════════════════════════════════════
# Trakt – #11 personal lists -> Plex
# ═══════════════════════════════════════════════════════════════════════════

class TestTraktPersonalLists:
    def test_get_personal_lists(self, monkeypatch):
        from trakt_utils import get_trakt_personal_lists
        lists = [{"name": "Watch Later", "ids": {"slug": "watch-later"}}]
        monkeypatch.setattr(
            "trakt_utils.trakt_request",
            lambda m, p, h, **kw: SimpleNamespace(json=lambda: lists),
        )
        assert get_trakt_personal_lists({}) == lists

    def test_get_personal_lists_error_returns_empty(self, monkeypatch):
        from trakt_utils import get_trakt_personal_lists

        def boom(*a, **k):
            raise ConnectionError("x")

        monkeypatch.setattr("trakt_utils.trakt_request", boom)
        assert get_trakt_personal_lists({}) == []

    def test_sync_personal_lists_creates_collection(self, monkeypatch):
        from trakt_utils import sync_personal_lists_to_plex

        lists = [{"name": "Watch Later", "ids": {"slug": "watch-later"}}]
        items = [{"type": "movie", "movie": {"ids": {"imdb": "tt0000001"}}}]

        def fake_request(method, path, headers, **kw):
            if path == "/users/me/lists":
                return SimpleNamespace(json=lambda: lists)
            if path.endswith("/items"):
                return SimpleNamespace(json=lambda: items)
            return SimpleNamespace(json=lambda: [])

        plex_item = MagicMock()
        plex_item.TYPE = "movie"

        movie_section = MagicMock()
        movie_section.type = "movie"
        plex = MagicMock()
        plex.library.sections.return_value = [movie_section]

        created = {}

        def fake_ensure(plex_, section, name, first_item=None):
            created["name"] = name
            return MagicMock()

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.find_item_by_guid", lambda plex_, guid: plex_item)
        monkeypatch.setattr("trakt_utils.ensure_collection", fake_ensure)

        sync_personal_lists_to_plex(plex, {})
        assert created.get("name") == "Watch Later"


# ═══════════════════════════════════════════════════════════════════════════
# Simkl – delta sync
# ═══════════════════════════════════════════════════════════════════════════

FAKE_HEADERS = {"Authorization": "Bearer x", "simkl-api-key": "k"}


def _resp(json_data):
    r = MagicMock()
    r.status_code = 200
    r.content = b"ok"
    r.json.return_value = json_data
    return r


class TestSimklActivities:
    SAMPLE = {
        "all": "2025-10-12T09:03:45Z",
        "movies": {"all": "2025-10-12T09:03:45Z", "rated_at": "2025-10-11T08:00:00Z"},
        "tv_shows": {"all": "2025-10-10T09:03:45Z", "rated_at": "2025-10-09T08:00:00Z"},
    }

    @patch("simkl_utils.simkl_request")
    def test_get_activities_uses_post(self, mock_req):
        from simkl_utils import get_simkl_last_activities
        mock_req.return_value = _resp(self.SAMPLE)
        result = get_simkl_last_activities(FAKE_HEADERS)
        assert result["all"] == self.SAMPLE["all"]
        mock_req.assert_called_once_with("POST", "/sync/activities", FAKE_HEADERS)

    @patch("simkl_utils.simkl_request")
    def test_get_activities_error_returns_none(self, mock_req):
        from simkl_utils import get_simkl_last_activities
        mock_req.side_effect = ConnectionError("boom")
        assert get_simkl_last_activities(FAKE_HEADERS) is None

    def test_save_load_update_roundtrip(self):
        import simkl_utils
        with tempfile.TemporaryDirectory() as tmp:
            fpath = os.path.join(tmp, "simkl_activities.json")
            with patch("simkl_utils.ACTIVITIES_FILE", fpath):
                simkl_utils.update_saved_activities(self.SAMPLE)
                loaded = simkl_utils._load_saved_activities()
                assert loaded["movies"]["rated_at"] == "2025-10-11T08:00:00Z"
                with open(fpath) as f:
                    assert json.load(f)["all"] == self.SAMPLE["all"]

    def test_has_changed_first_run(self):
        from simkl_utils import has_simkl_category_changed
        with patch("simkl_utils._load_saved_activities", return_value={}):
            changed, ts = has_simkl_category_changed("all")
            assert changed is True and ts is None

    def test_has_changed_no_current_fails_open(self):
        from simkl_utils import has_simkl_category_changed
        with patch("simkl_utils._load_saved_activities", return_value=self.SAMPLE):
            changed, ts = has_simkl_category_changed("movies.rated_at")
            assert changed is True
            assert ts == "2025-10-11T08:00:00Z"

    def test_has_changed_true_when_current_newer(self):
        from simkl_utils import has_simkl_category_changed
        current = {"movies": {"rated_at": "2025-12-01T00:00:00Z"}}
        with patch("simkl_utils._load_saved_activities", return_value=self.SAMPLE):
            changed, _ = has_simkl_category_changed("movies.rated_at", current)
            assert changed is True

    def test_has_changed_false_when_unchanged(self):
        from simkl_utils import has_simkl_category_changed
        current = {"movies": {"rated_at": "2025-10-11T08:00:00Z"}}
        with patch("simkl_utils._load_saved_activities", return_value=self.SAMPLE):
            changed, _ = has_simkl_category_changed("movies.rated_at", current)
            assert changed is False


# ═══════════════════════════════════════════════════════════════════════════
# Simkl – all-items + #12 hold/dropped
# ═══════════════════════════════════════════════════════════════════════════

class TestSimklAllItems:
    SAMPLE = {
        "movies": [
            {"movie": {"title": "Inception", "year": 2010, "ids": {"imdb": "tt1375666"}},
             "last_watched_at": "2025-01-15T10:00:00Z", "status": "completed"},
            {"movie": {"title": "Dune", "year": 2021, "ids": {"imdb": "tt1160419"}},
             "status": "dropped"},
        ],
        "shows": [
            {"show": {"title": "Breaking Bad", "ids": {"imdb": "tt0903747"}},
             "status": "hold",
             "seasons": [{"number": 1, "episodes": [
                 {"number": 1, "watched_at": "2025-02-01T12:00:00Z"},
                 {"number": 2, "watched_at": "2025-02-02T12:00:00Z"}]}]},
        ],
    }

    @patch("simkl_utils.simkl_request")
    def test_no_params_base_endpoint(self, mock_req):
        from simkl_utils import get_simkl_all_items
        mock_req.return_value = _resp(self.SAMPLE)
        result = get_simkl_all_items(FAKE_HEADERS)
        assert "movies" in result
        assert mock_req.call_args[0][1] == "/sync/all-items"

    @patch("simkl_utils.simkl_request")
    def test_media_type_and_date_from(self, mock_req):
        from simkl_utils import get_simkl_all_items
        mock_req.return_value = _resp(self.SAMPLE)
        get_simkl_all_items(FAKE_HEADERS, "movies", date_from="2025-01-01T00:00:00Z")
        assert mock_req.call_args[0][1] == "/sync/all-items/movies/"
        assert mock_req.call_args[1]["params"]["date_from"] == "2025-01-01T00:00:00Z"

    @patch("simkl_utils.simkl_request")
    def test_status_endpoint(self, mock_req):
        from simkl_utils import get_simkl_all_items
        mock_req.return_value = _resp(self.SAMPLE)
        get_simkl_all_items(FAKE_HEADERS, "shows", status="dropped")
        assert mock_req.call_args[0][1] == "/sync/all-items/shows/dropped/"

    @patch("simkl_utils.simkl_request")
    def test_extended_and_episode_watched(self, mock_req):
        from simkl_utils import get_simkl_all_items
        mock_req.return_value = _resp(self.SAMPLE)
        get_simkl_all_items(FAKE_HEADERS, extended="full", episode_watched_at=True)
        params = mock_req.call_args[1]["params"]
        assert params["extended"] == "full"
        assert params["episode_watched_at"] == "yes"

    @patch("simkl_utils.simkl_request")
    def test_null_response_returns_empty(self, mock_req):
        from simkl_utils import get_simkl_all_items
        mock_req.return_value = _resp(None)
        assert get_simkl_all_items(FAKE_HEADERS) == {}

    def test_parse_movies_and_episodes(self):
        from simkl_utils import parse_all_items_response
        movies, episodes = parse_all_items_response(self.SAMPLE)
        assert movies["imdb://tt1375666"][0] == "Inception"
        assert movies["imdb://tt1375666"][1] == 2010
        assert len(episodes) == 2
        codes = {v[1] for v in episodes.values()}
        assert codes == {"S01E01", "S01E02"}

    def test_parse_empty(self):
        from simkl_utils import parse_all_items_response
        assert parse_all_items_response({}) == ({}, {})

    @patch("simkl_utils.simkl_request")
    def test_items_by_status_filters(self, mock_req):
        from simkl_utils import get_simkl_items_by_status
        mock_req.return_value = _resp(self.SAMPLE)
        dropped = get_simkl_items_by_status(FAKE_HEADERS, "dropped")
        assert len(dropped["movies"]) == 1
        assert dropped["movies"][0]["movie"]["title"] == "Dune"
        assert dropped["shows"] == []

        mock_req.return_value = _resp(self.SAMPLE)
        held = get_simkl_items_by_status(FAKE_HEADERS, "hold")
        assert len(held["shows"]) == 1
        assert held["movies"] == []

    def test_items_by_status_invalid_raises(self):
        from simkl_utils import get_simkl_items_by_status
        import pytest
        with pytest.raises(ValueError):
            get_simkl_items_by_status(FAKE_HEADERS, "bogus")
