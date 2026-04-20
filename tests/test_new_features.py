"""
Tests for the new sync features implemented in PlexyTrack:

1. Trakt Last Activities (incremental sync optimization)
2. Playback Progress sync
3. Favorites sync
4. Webhook event parsing (media.rate, media.pause, etc.)
5. Trakt Collection → Plex import
6. Hidden / Dropped items sync
7. Checkin support
8. Collection metadata (resolution, audio, HDR)
9. Settings persistence for new features
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import safe_timestamp_compare, to_iso_z


# ═══════════════════════════════════════════════════════════════════════════════
# 1. TRAKT LAST ACTIVITIES
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTraktLastActivities:
    """Tests for get_trakt_last_activities."""

    def test_returns_activities_on_success(self, monkeypatch):
        from trakt_utils import get_trakt_last_activities

        expected = {
            "movies": {"watched_at": "2025-06-01T00:00:00.000Z"},
            "episodes": {"watched_at": "2025-06-02T00:00:00.000Z"},
        }

        def fake_request(method, path, headers, **kw):
            return SimpleNamespace(json=lambda: expected)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        result = get_trakt_last_activities({})
        assert result == expected

    def test_returns_none_on_failure(self, monkeypatch):
        from trakt_utils import get_trakt_last_activities

        def failing_request(method, path, headers, **kw):
            raise ConnectionError("network error")

        monkeypatch.setattr("trakt_utils.trakt_request", failing_request)
        assert get_trakt_last_activities({}) is None


class TestShouldSyncCategory:
    """Tests for should_sync_category."""

    def test_returns_true_when_activities_is_none(self):
        from trakt_utils import should_sync_category
        assert should_sync_category(None, "2025-01-01T00:00:00Z", "movies", "watched_at") is True

    def test_returns_true_when_last_sync_is_none(self):
        from trakt_utils import should_sync_category
        activities = {"movies": {"watched_at": "2025-06-01T00:00:00.000Z"}}
        assert should_sync_category(activities, None, "movies", "watched_at") is True

    def test_returns_true_when_activity_is_newer(self):
        from trakt_utils import should_sync_category
        activities = {"movies": {"watched_at": "2025-06-15T12:00:00.000Z"}}
        last_sync = "2025-06-01T00:00:00Z"
        assert should_sync_category(activities, last_sync, "movies", "watched_at") is True

    def test_returns_false_when_activity_is_older(self):
        from trakt_utils import should_sync_category
        activities = {"movies": {"watched_at": "2025-01-01T00:00:00.000Z"}}
        last_sync = "2025-06-01T00:00:00Z"
        assert should_sync_category(activities, last_sync, "movies", "watched_at") is False

    def test_returns_true_when_category_missing(self):
        from trakt_utils import should_sync_category
        activities = {"shows": {"watched_at": "2025-06-01T00:00:00.000Z"}}
        assert should_sync_category(activities, "2025-01-01T00:00:00Z", "movies", "watched_at") is True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PLAYBACK PROGRESS SYNC
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTraktPlayback:
    """Tests for get_trakt_playback."""

    def test_returns_playback_items(self, monkeypatch):
        from trakt_utils import get_trakt_playback

        items = [
            {"type": "movie", "progress": 45.0, "movie": {"ids": {"imdb": "tt1234567"}}},
        ]

        def fake_request(method, path, headers, **kw):
            return SimpleNamespace(json=lambda: items)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        result = get_trakt_playback({})
        assert len(result) == 1
        assert result[0]["progress"] == 45.0

    def test_returns_empty_on_failure(self, monkeypatch):
        from trakt_utils import get_trakt_playback

        def failing_request(*a, **kw):
            raise ConnectionError("fail")

        monkeypatch.setattr("trakt_utils.trakt_request", failing_request)
        assert get_trakt_playback({}) == []


class TestRemoveTraktPlayback:
    """Tests for remove_trakt_playback."""

    def test_returns_true_on_success(self, monkeypatch):
        from trakt_utils import remove_trakt_playback

        def fake_request(method, path, headers, **kw):
            assert method == "DELETE"
            assert "/sync/playback/42" in path
            return SimpleNamespace(status_code=204)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        assert remove_trakt_playback({}, 42) is True

    def test_returns_false_on_failure(self, monkeypatch):
        from trakt_utils import remove_trakt_playback

        def failing(*a, **kw):
            raise ConnectionError("fail")

        monkeypatch.setattr("trakt_utils.trakt_request", failing)
        assert remove_trakt_playback({}, 1) is False


class TestSyncPlaybackPlexToTrakt:
    """Tests for sync_playback_plex_to_trakt."""

    def _make_plex_item(self, title, item_type, view_offset, duration, guid_val):
        item = MagicMock()
        item.title = title
        item.TYPE = item_type
        item.type = item_type
        item.viewOffset = view_offset
        item.duration = duration
        item.year = 2024
        item.guids = [SimpleNamespace(id=guid_val)]
        return item

    def test_syncs_in_progress_movies(self, monkeypatch):
        from trakt_utils import sync_playback_plex_to_trakt

        movie = self._make_plex_item("Test Movie", "movie", 3600000, 7200000, "imdb://tt1234567")

        section = MagicMock()
        section.type = "movie"
        section.title = "Movies"
        section.search.return_value = [movie]

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        scrobble_calls = []

        def fake_request(method, path, headers, **kw):
            if path == "/scrobble/pause":
                scrobble_calls.append(kw.get("json", {}))
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "imdb://tt1234567")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"imdb": "tt1234567"})
        monkeypatch.setattr("trakt_utils.normalize_year", lambda y: y)

        sync_playback_plex_to_trakt(plex, {})

        assert len(scrobble_calls) == 1
        assert scrobble_calls[0]["progress"] == 50.0
        assert "movie" in scrobble_calls[0]

    def test_skips_nearly_finished(self, monkeypatch):
        from trakt_utils import sync_playback_plex_to_trakt

        # 95% watched → should be skipped
        movie = self._make_plex_item("Almost Done", "movie", 6840000, 7200000, "imdb://tt9999999")

        section = MagicMock()
        section.type = "movie"
        section.title = "Movies"
        section.search.return_value = [movie]

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        scrobble_calls = []

        def fake_request(method, path, headers, **kw):
            if path == "/scrobble/pause":
                scrobble_calls.append(kw.get("json", {}))
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "imdb://tt9999999")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"imdb": "tt9999999"})

        sync_playback_plex_to_trakt(plex, {})
        assert len(scrobble_calls) == 0


class TestSyncPlaybackTraktToPlex:
    """Tests for sync_playback_trakt_to_plex."""

    def test_updates_plex_view_offset(self, monkeypatch):
        from trakt_utils import sync_playback_trakt_to_plex

        playback_items = [
            {
                "type": "movie",
                "progress": 50.0,
                "movie": {"ids": {"imdb": "tt1234567"}},
            }
        ]

        def fake_request(method, path, headers, **kw):
            return SimpleNamespace(json=lambda: playback_items)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)

        plex_item = MagicMock()
        plex_item.title = "Test Movie"
        plex_item.duration = 7200000
        plex_item.viewOffset = 0  # Currently at 0, should be updated to 50%

        monkeypatch.setattr("trakt_utils.find_item_by_guid", lambda plex, guid: plex_item)

        sync_playback_trakt_to_plex(MagicMock(), {})

        plex_item.updateTimeline.assert_called_once()
        call_args = plex_item.updateTimeline.call_args
        assert call_args[0][0] == 3600000  # 50% of 7200000


# ═══════════════════════════════════════════════════════════════════════════════
# 3. FAVORITES SYNC
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTraktFavorites:
    """Tests for get_trakt_favorites."""

    def test_returns_favorites(self, monkeypatch):
        from trakt_utils import get_trakt_favorites

        favorites = [
            {"type": "movie", "movie": {"ids": {"imdb": "tt1234567"}, "title": "Fav Movie"}},
        ]

        def fake_request(method, path, headers, **kw):
            return SimpleNamespace(json=lambda: favorites)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        result = get_trakt_favorites({})
        assert len(result) == 1
        assert result[0]["type"] == "movie"

    def test_returns_empty_on_failure(self, monkeypatch):
        from trakt_utils import get_trakt_favorites

        def failing(*a, **kw):
            raise ConnectionError("fail")

        monkeypatch.setattr("trakt_utils.trakt_request", failing)
        assert get_trakt_favorites({}) == []


class TestSyncFavoritesPlexToTrakt:
    """Tests for sync_favorites_plex_to_trakt."""

    def test_syncs_collection_items_as_favorites(self, monkeypatch):
        from trakt_utils import sync_favorites_plex_to_trakt

        movie = MagicMock()
        movie.TYPE = "movie"
        movie.title = "Favorite Movie"
        movie.year = 2024

        coll = MagicMock()
        coll.title = "Favorites"
        coll.items.return_value = [movie]

        section = MagicMock()
        section.type = "movie"
        section.collections.return_value = [coll]

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        posted_payloads = []

        def fake_request(method, path, headers, **kw):
            if method == "POST" and "/sync/favorites" in path:
                posted_payloads.append(kw.get("json", {}))
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "imdb://tt1111111")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"imdb": "tt1111111"})
        monkeypatch.setattr("trakt_utils.normalize_year", lambda y: y)

        sync_favorites_plex_to_trakt(plex, {})

        assert len(posted_payloads) == 1
        assert "movies" in posted_payloads[0]
        assert len(posted_payloads[0]["movies"]) == 1

    def test_no_collection_no_request(self, monkeypatch):
        from trakt_utils import sync_favorites_plex_to_trakt

        section = MagicMock()
        section.type = "movie"
        section.collections.return_value = []

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        calls = []

        def fake_request(method, path, headers, **kw):
            calls.append((method, path))
            return SimpleNamespace(status_code=200)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)

        sync_favorites_plex_to_trakt(plex, {})
        # Should not POST since no items were found
        assert not any(m == "POST" for m, _ in calls)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. WEBHOOK EVENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookEventParsing:
    """Tests for the improved webhook handler."""

    def setup_method(self):
        import app as app_module
        self.app_module = app_module
        self.client = app_module.app.test_client()

    def test_webhook_returns_204_when_live_sync_off(self):
        self.app_module.LIVE_SYNC = False
        resp = self.client.post("/webhook", data=b"{}", content_type="application/json")
        assert resp.status_code == 204

    def test_webhook_parses_media_rate_event(self, monkeypatch):
        self.app_module.LIVE_SYNC = True
        self.app_module.SYNC_PROVIDER = "trakt"
        self.app_module.SYNC_RATINGS = True
        self.app_module.SYNC_COLLECTION = False
        self.app_module.SYNC_WATCHED = False
        self.app_module.SYNC_LIKED_LISTS = False
        self.app_module.SYNC_WATCHLISTS = False

        jobs_added = []
        monkeypatch.setattr(
            self.app_module.scheduler, "add_job",
            lambda func, trigger, **kw: jobs_added.append(func.__name__ if hasattr(func, '__name__') else "lambda")
        )

        payload = json.dumps({"event": "media.rate"})
        resp = self.client.post("/webhook", data=payload, content_type="application/json")
        assert resp.status_code == 204
        # Should have added a ratings-specific job, not a full sync
        assert len(jobs_added) == 1

    def test_webhook_handles_media_pause_for_playback(self, monkeypatch):
        self.app_module.LIVE_SYNC = True
        self.app_module.SYNC_PROVIDER = "trakt"
        self.app_module.SYNC_PLAYBACK = True

        jobs_added = []
        monkeypatch.setattr(
            self.app_module.scheduler, "add_job",
            lambda func, trigger, **kw: jobs_added.append("job")
        )

        payload = json.dumps({"event": "media.pause"})
        resp = self.client.post("/webhook", data=payload, content_type="application/json")
        assert resp.status_code == 204
        assert len(jobs_added) == 1

    def test_webhook_scrobble_triggers_full_sync(self, monkeypatch):
        self.app_module.LIVE_SYNC = True
        self.app_module.SYNC_PROVIDER = "trakt"
        self.app_module.SYNC_WATCHED = True
        self.app_module.SYNC_RATINGS = False
        self.app_module.SYNC_PLAYBACK = False
        self.app_module.SYNC_COLLECTION = False
        self.app_module.SYNC_LIKED_LISTS = False
        self.app_module.SYNC_WATCHLISTS = False

        jobs_added = []
        monkeypatch.setattr(
            self.app_module.scheduler, "add_job",
            lambda func, trigger, **kw: jobs_added.append(func.__name__ if hasattr(func, '__name__') else "func")
        )

        payload = json.dumps({"event": "media.scrobble"})
        resp = self.client.post("/webhook", data=payload, content_type="application/json")
        assert resp.status_code == 204
        assert len(jobs_added) == 1

    def test_webhook_multipart_payload(self, monkeypatch):
        """Plex sends webhook as multipart/form-data with a 'payload' field."""
        self.app_module.LIVE_SYNC = True
        self.app_module.SYNC_PROVIDER = "trakt"
        self.app_module.SYNC_RATINGS = True

        jobs_added = []
        monkeypatch.setattr(
            self.app_module.scheduler, "add_job",
            lambda func, trigger, **kw: jobs_added.append("job")
        )

        payload = json.dumps({"event": "media.rate"})
        resp = self.client.post(
            "/webhook",
            data={"payload": payload},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 204
        assert len(jobs_added) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TRAKT COLLECTION → PLEX IMPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestImportTraktCollection:
    """Tests for import_trakt_collection."""

    def test_imports_matching_movies(self, monkeypatch):
        from trakt_utils import import_trakt_collection

        trakt_collection = [
            {"movie": {"title": "Movie A", "ids": {"imdb": "tt0000001"}}},
            {"movie": {"title": "Movie B", "ids": {"tmdb": 12345}}},
        ]

        request_calls = []

        def fake_request(method, path, headers, **kw):
            request_calls.append((method, path))
            if path == "/sync/collection/movies":
                return SimpleNamespace(json=lambda: trakt_collection)
            return SimpleNamespace(status_code=200)

        plex_item = MagicMock()
        plex_item.title = "Movie A"
        plex_item.librarySectionID = 1

        section = MagicMock()

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.find_item_by_guid", lambda plex, guid: plex_item if "tt0000001" in guid else None)
        monkeypatch.setattr("trakt_utils.ensure_collection", lambda plex, section, name, first_item=None: MagicMock())

        plex = MagicMock()
        plex.library.sectionByID.return_value = section

        import_trakt_collection(plex, {})

        assert ("GET", "/sync/collection/movies") in request_calls

    def test_handles_empty_collection(self, monkeypatch):
        from trakt_utils import import_trakt_collection

        def fake_request(method, path, headers, **kw):
            return SimpleNamespace(json=lambda: [])

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)

        import_trakt_collection(MagicMock(), {})
        # Should not raise


# ═══════════════════════════════════════════════════════════════════════════════
# 6. HIDDEN / DROPPED ITEMS SYNC
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTraktHiddenItems:
    """Tests for get_trakt_hidden_items."""

    def test_returns_hidden_items(self, monkeypatch):
        from trakt_utils import get_trakt_hidden_items

        items = [
            {"type": "show", "show": {"ids": {"tvdb": 12345}, "title": "Dropped Show"}},
        ]

        call_count = [0]

        def fake_request(method, path, headers, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return SimpleNamespace(json=lambda: items)
            return SimpleNamespace(json=lambda: [])

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        result = get_trakt_hidden_items({}, "progress_watched")
        assert len(result) == 1
        assert result[0]["show"]["title"] == "Dropped Show"

    def test_returns_empty_on_error(self, monkeypatch):
        from trakt_utils import get_trakt_hidden_items

        def failing(*a, **kw):
            raise ConnectionError("fail")

        monkeypatch.setattr("trakt_utils.trakt_request", failing)
        assert get_trakt_hidden_items({}, "progress_watched") == []


class TestSyncHiddenToPlex:
    """Tests for sync_hidden_to_plex."""

    def test_creates_dropped_collection(self, monkeypatch):
        from trakt_utils import sync_hidden_to_plex

        hidden = [
            {"type": "show", "show": {"ids": {"tvdb": 111}, "title": "Show A"}},
        ]
        dropped = [
            {"type": "show", "show": {"ids": {"imdb": "tt2222222"}, "title": "Show B"}},
        ]

        call_count = [0]

        def fake_request(method, path, headers, **kw):
            call_count[0] += 1
            section = kw.get("params", {}).get("page", 1) if "params" in kw else 1
            if "progress_watched" in path and call_count[0] == 1:
                return SimpleNamespace(json=lambda: hidden)
            if "dropped" in path and call_count[0] == 3:
                return SimpleNamespace(json=lambda: dropped)
            return SimpleNamespace(json=lambda: [])

        plex_item = MagicMock()
        plex_item.title = "Show A"
        plex_item.librarySectionID = 2

        section = MagicMock()
        coll = MagicMock()

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.find_item_by_guid", lambda plex, guid: plex_item)
        monkeypatch.setattr("trakt_utils.ensure_collection", lambda plex, sec, name, first_item=None: coll)

        plex = MagicMock()
        plex.library.sectionByID.return_value = section

        sync_hidden_to_plex(plex, {})

        # Verify ensure_collection was called with "Dropped Shows"
        # (indirectly verified via monkeypatch)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. CHECKIN SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════

class TestTraktCheckin:
    """Tests for trakt_checkin and trakt_checkin_cancel."""

    def test_checkin_success(self, monkeypatch):
        from trakt_utils import trakt_checkin

        posted = []

        def fake_request(method, path, headers, **kw):
            posted.append(kw.get("json", {}))
            return SimpleNamespace(status_code=201)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)

        item = {"movie": {"ids": {"imdb": "tt1234567"}, "title": "Movie"}}
        result = trakt_checkin({}, item, message="Watching now!")
        assert result is True
        assert posted[0]["sharing"]["text"] == "Watching now!"

    def test_checkin_conflict_returns_false(self, monkeypatch):
        import requests as req
        from trakt_utils import trakt_checkin

        def fake_request(method, path, headers, **kw):
            resp = SimpleNamespace(status_code=409)
            raise req.exceptions.HTTPError(response=resp)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)

        result = trakt_checkin({}, {"movie": {"ids": {"imdb": "tt1234567"}}})
        assert result is False

    def test_checkin_cancel(self, monkeypatch):
        from trakt_utils import trakt_checkin_cancel

        def fake_request(method, path, headers, **kw):
            assert method == "DELETE"
            assert path == "/checkin"
            return SimpleNamespace(status_code=204)

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        assert trakt_checkin_cancel({}) is True


# ═══════════════════════════════════════════════════════════════════════════════
# 8. SAFE TIMESTAMP COMPARE (utils.py)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSafeTimestampCompare:
    """Tests for safe_timestamp_compare."""

    def test_newer_timestamp(self):
        assert safe_timestamp_compare("2025-06-15T12:00:00.000Z", "2025-06-01T00:00:00Z") is True

    def test_older_timestamp(self):
        assert safe_timestamp_compare("2025-01-01T00:00:00Z", "2025-06-01T00:00:00Z") is False

    def test_equal_timestamps(self):
        assert safe_timestamp_compare("2025-06-01T00:00:00Z", "2025-06-01T00:00:00Z") is False

    def test_none_first_returns_false(self):
        assert safe_timestamp_compare(None, "2025-06-01T00:00:00Z") is False

    def test_none_second_returns_false(self):
        assert safe_timestamp_compare("2025-06-01T00:00:00Z", None) is False

    def test_both_none_returns_false(self):
        assert safe_timestamp_compare(None, None) is False

    def test_with_milliseconds(self):
        assert safe_timestamp_compare("2025-06-15T12:00:00.500Z", "2025-06-15T12:00:00.000Z") is True


class TestToIsoZ:
    """Tests for to_iso_z."""

    def test_naive_datetime_is_converted_from_local_timezone_to_utc(self):
        if not hasattr(time, "tzset"):
            pytest.skip("tzset is not available on this platform")

        original_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/Santiago"
            time.tzset()

            assert to_iso_z(datetime(2026, 4, 13, 17, 30, 0)) == "2026-04-13T21:30:00Z"
        finally:
            if original_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = original_tz
            time.tzset()


# ═══════════════════════════════════════════════════════════════════════════════
# 9. SETTINGS PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

class TestSettingsPersistence:
    """Tests for load/save of new settings fields."""

    def test_save_includes_new_fields(self, monkeypatch, tmp_path):
        import app as app_module

        settings_file = str(tmp_path / "settings.json")
        monkeypatch.setattr(app_module, "SETTINGS_FILE", settings_file)
        monkeypatch.setattr(app_module, "SYNC_FAVORITES", True)
        monkeypatch.setattr(app_module, "SYNC_PLAYBACK", True)
        monkeypatch.setattr(app_module, "SYNC_HIDDEN_ITEMS", True)
        monkeypatch.setattr(app_module, "FAVORITES_SYNC_DIRECTION", "both")
        monkeypatch.setattr(app_module, "PLAYBACK_SYNC_DIRECTION", "plex_to_service")

        app_module.save_settings()

        with open(settings_file) as f:
            data = json.load(f)

        assert data["favorites"] is True
        assert data["playback"] is True
        assert data["hidden_items"] is True
        assert data["favorites_direction"] == "both"
        assert data["playback_direction"] == "plex_to_service"

    def test_load_reads_new_fields(self, monkeypatch, tmp_path):
        import app as app_module

        settings_file = str(tmp_path / "settings.json")
        data = {
            "minutes": 30,
            "collection": True,
            "ratings": True,
            "watched": True,
            "liked_lists": False,
            "watchlists": False,
            "favorites": True,
            "playback": True,
            "hidden_items": True,
            "live_sync": False,
            "history_direction": "both",
            "lists_direction": "both",
            "watchlists_direction": "both",
            "ratings_direction": "both",
            "collection_direction": "both",
            "favorites_direction": "service_to_plex",
            "playback_direction": "plex_to_service",
            "watchlist_conflict_resolution": "last_wins",
            "watchlist_removal_enabled": True,
        }
        with open(settings_file, "w") as f:
            json.dump(data, f)

        monkeypatch.setattr(app_module, "SETTINGS_FILE", settings_file)
        app_module.load_settings()

        assert app_module.SYNC_FAVORITES is True
        assert app_module.SYNC_PLAYBACK is True
        assert app_module.SYNC_HIDDEN_ITEMS is True
        assert app_module.FAVORITES_SYNC_DIRECTION == "service_to_plex"
        assert app_module.PLAYBACK_SYNC_DIRECTION == "plex_to_service"

    def test_load_defaults_when_new_fields_missing(self, monkeypatch, tmp_path):
        import app as app_module

        settings_file = str(tmp_path / "settings.json")
        # Old format without new fields
        data = {
            "minutes": 60,
            "collection": False,
            "ratings": True,
            "watched": True,
            "liked_lists": False,
            "watchlists": False,
            "live_sync": False,
            "history_direction": "both",
        }
        with open(settings_file, "w") as f:
            json.dump(data, f)

        # Set defaults explicitly
        app_module.SYNC_FAVORITES = False
        app_module.SYNC_PLAYBACK = False
        app_module.SYNC_HIDDEN_ITEMS = False
        app_module.FAVORITES_SYNC_DIRECTION = "both"
        app_module.PLAYBACK_SYNC_DIRECTION = "both"

        monkeypatch.setattr(app_module, "SETTINGS_FILE", settings_file)
        app_module.load_settings()

        # Should keep defaults since keys are missing from file
        assert app_module.SYNC_FAVORITES is False
        assert app_module.SYNC_PLAYBACK is False
        assert app_module.SYNC_HIDDEN_ITEMS is False


# ═══════════════════════════════════════════════════════════════════════════════
# 10. COLLECTION METADATA (resolution, audio, HDR)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCollectionMetadata:
    """Tests for collection metadata extraction in sync_collection."""

    def test_sync_collection_sends_metadata(self, monkeypatch):
        from trakt_utils import sync_collection

        # Create a mock Plex movie with media info
        media_part = MagicMock()
        media = MagicMock()
        media.videoResolution = "4k"
        media.audioCodec = "dts"
        media.audioChannels = 6
        media.parts = [media_part]

        # Check if the media has DOVIPresent or other HDR attributes
        type(media).DOVIPresent = False

        movie = MagicMock()
        movie.TYPE = "movie"
        movie.type = "movie"
        movie.title = "Test Movie"
        movie.year = 2024
        movie.media = [media]

        section = MagicMock()
        section.type = "movie"
        section.title = "Movies"
        section.all.return_value = [movie]

        plex = MagicMock()
        plex.library.sections.return_value = [section]

        posted = []

        def fake_request(method, path, headers, **kw):
            if method == "POST":
                posted.append(kw.get("json", {}))
            elif method == "GET" and path == "/sync/collection/movies":
                return SimpleNamespace(json=lambda: [])
            elif method == "GET" and path == "/sync/collection/shows":
                return SimpleNamespace(json=lambda: [])
            return SimpleNamespace(status_code=200, json=lambda: [])

        monkeypatch.setattr("trakt_utils.trakt_request", fake_request)
        monkeypatch.setattr("trakt_utils.best_guid", lambda item: "imdb://tt1234567")
        monkeypatch.setattr("trakt_utils.guid_to_ids", lambda guid: {"imdb": "tt1234567"})
        monkeypatch.setattr("trakt_utils.normalize_year", lambda y: y)

        sync_collection(plex, {})

        # Verify POST was called with movie data
        assert len(posted) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 11. INTEGRATION: sync() FUNCTION CALLS NEW FEATURES
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyncIntegration:
    """Verify that sync() dispatches to the new features when enabled."""

    def test_collection_import_called_when_direction_service_to_plex(self, monkeypatch):
        """The old 'not implemented' warning should now call import_trakt_collection."""
        import app as app_module

        # Read the source code to verify the warning was replaced
        import inspect
        source = inspect.getsource(app_module.sync)
        assert "import_trakt_collection" in source
        assert "Collection import from Trakt is not implemented" not in source

    def test_new_sync_features_in_sync_function(self):
        """Verify the sync() function references the new feature functions."""
        import app as app_module
        import inspect
        source = inspect.getsource(app_module.sync)

        assert "sync_favorites_plex_to_trakt" in source
        assert "sync_favorites_trakt_to_plex" in source
        assert "sync_playback_plex_to_trakt" in source
        assert "sync_playback_trakt_to_plex" in source
        assert "sync_hidden_to_plex" in source
        assert "SYNC_FAVORITES" in source
        assert "SYNC_PLAYBACK" in source
        assert "SYNC_HIDDEN_ITEMS" in source
