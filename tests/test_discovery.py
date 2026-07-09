"""Tests for connections #6 & #7: recommendations + trending -> Plex collections.

Covers the shared utils helpers (ids_to_guid, match_guids_to_plex,
sync_items_to_collection incl. reconciliation), the Trakt discovery functions,
and the Simkl trending CDN fetch. All network / Plex access is mocked.
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import utils
import trakt_utils as tu
import simkl_utils as su


# ---------------------------------------------------------------------------
# utils helpers
# ---------------------------------------------------------------------------

class TestIdsToGuid:
    def test_prefers_imdb(self):
        assert utils.ids_to_guid({"imdb": "tt1", "tmdb": 5}) == "imdb://tt1"

    def test_falls_back_to_anidb(self):
        assert utils.ids_to_guid({"anidb": 42}) == "anidb://42"

    def test_none(self):
        assert utils.ids_to_guid({}) is None
        assert utils.ids_to_guid(None) is None


class TestSyncItemsToCollection:
    def _item(self, guid_id, sid=1):
        it = MagicMock()
        it.librarySectionID = sid
        it.guids = [SimpleNamespace(id=guid_id)]
        return it

    def test_adds_new_items(self, monkeypatch):
        a = self._item("imdb://A")
        b = self._item("imdb://B")
        coll = MagicMock()
        coll.items.return_value = [a]  # A already in collection
        section = MagicMock()
        plex = MagicMock()
        plex.library.sectionByID.return_value = section
        monkeypatch.setattr(utils, "ensure_collection", lambda p, s, n, first_item=None: coll)

        total = utils.sync_items_to_collection(plex, [a, b], "Recommended")
        assert total == 2
        coll.addItems.assert_called_once_with([b])
        coll.removeItems.assert_not_called()  # no reconcile

    def test_reconcile_removes_stale(self, monkeypatch):
        a = self._item("imdb://A")
        stale = self._item("imdb://OLD")
        coll = MagicMock()
        coll.items.return_value = [a, stale]  # OLD no longer targeted
        section = MagicMock()
        plex = MagicMock()
        plex.library.sectionByID.return_value = section
        monkeypatch.setattr(utils, "ensure_collection", lambda p, s, n, first_item=None: coll)

        total = utils.sync_items_to_collection(plex, [a], "Trending", reconcile=True)
        assert total == 1
        coll.removeItems.assert_called_once()
        removed = coll.removeItems.call_args[0][0]
        assert removed == [stale]

    def test_empty_target_never_wipes(self, monkeypatch):
        called = []
        monkeypatch.setattr(utils, "ensure_collection", lambda *a, **k: called.append(1))
        assert utils.sync_items_to_collection(MagicMock(), [], "X", reconcile=True) == 0
        assert called == []


# ---------------------------------------------------------------------------
# Trakt discovery
# ---------------------------------------------------------------------------

class TestTraktDiscovery:
    def test_extract_guids_wrapped_and_flat(self):
        # trending: wrapped in "movie"; popular: flat
        wrapped = [{"watchers": 10, "movie": {"ids": {"imdb": "ttW"}}}]
        flat = [{"ids": {"imdb": "ttF"}}]
        assert tu._trakt_items_to_guids(wrapped, "movies") == ["imdb://ttW"]
        assert tu._trakt_items_to_guids(flat, "movies") == ["imdb://ttF"]

    def test_get_recommendations(self, monkeypatch):
        seen = {}

        def fake(method, path, headers, **kw):
            seen["path"] = path
            seen["params"] = kw.get("params")
            return SimpleNamespace(json=lambda: [{"ids": {"imdb": "tt1"}}])

        monkeypatch.setattr(tu, "trakt_request", fake)
        result = tu.get_trakt_recommendations({}, "movies", limit=25)
        assert result == [{"ids": {"imdb": "tt1"}}]
        assert seen["path"] == "/recommendations/movies"
        assert seen["params"] == {"limit": 25}

    def test_get_discovery_path(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(tu, "trakt_request",
                            lambda m, p, h, **kw: seen.update(path=p) or SimpleNamespace(json=lambda: []))
        tu.get_trakt_discovery({}, "shows", "anticipated")
        assert seen["path"] == "/shows/anticipated"

    def test_sync_recommendations_materializes(self, monkeypatch):
        monkeypatch.setattr(tu, "get_trakt_recommendations",
                            lambda h, mt, **k: [{"ids": {"imdb": f"tt-{mt}"}}])
        matched = {"calls": []}
        monkeypatch.setattr(tu, "match_guids_to_plex",
                            lambda plex, guids: list(guids))
        monkeypatch.setattr(tu, "sync_items_to_collection",
                            lambda plex, items, name, **k: matched["calls"].append((name, list(items)), ) or len(items))

        total = tu.sync_trakt_recommendations_to_plex(MagicMock(), {})
        # movies + shows -> 2 items, one collection name
        assert total == 2
        names = {c[0] for c in matched["calls"]}
        assert names == {"Recommended by Trakt"}


# ---------------------------------------------------------------------------
# Simkl trending (CDN)
# ---------------------------------------------------------------------------

class TestSimklTrending:
    SAMPLE = {
        "tv": [{"title": "HotD", "ids": {"imdb": "tt11198330", "tvdb": "371572"}}],
        "anime": [{"title": "AoT", "ids": {"mal": "16498", "anidb": "9541"}}],
    }

    @patch("simkl_utils.requests.get")
    def test_get_trending_fetches_cdn(self, mock_get):
        resp = MagicMock()
        resp.json.return_value = self.SAMPLE
        resp.raise_for_status.return_value = None
        mock_get.return_value = resp
        data = su.get_simkl_trending(period="week")
        assert "tv" in data
        url = mock_get.call_args[0][0]
        assert url.endswith("/trending/week_100.json")

    @patch("simkl_utils.requests.get", side_effect=Exception("net"))
    def test_get_trending_error(self, mock_get):
        assert su.get_simkl_trending() == {}

    def test_extract_guids(self):
        guids = su._simkl_trending_guids(self.SAMPLE)
        assert "imdb://tt11198330" in guids
        assert "anidb://9541" in guids

    def test_sync_trending_materializes(self, monkeypatch):
        monkeypatch.setattr(su, "get_simkl_trending", lambda **k: self.SAMPLE)
        monkeypatch.setattr(su, "match_guids_to_plex", lambda plex, guids: list(guids))
        captured = {}
        monkeypatch.setattr(su, "sync_items_to_collection",
                            lambda plex, items, name, **k: captured.update(name=name, n=len(items)) or len(items))
        total = su.sync_simkl_trending_to_plex(MagicMock())
        assert total == 2
        assert captured["name"] == "Trending on Simkl"


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------

class TestWiring:
    def test_sync_inner_wires_discovery(self):
        import app
        import inspect
        src = inspect.getsource(app._sync_inner)
        assert "SYNC_RECOMMENDATIONS" in src
        assert "sync_trakt_recommendations_to_plex" in src
        assert "sync_simkl_trending_to_plex" in src
