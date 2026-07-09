"""Tests for connection #4: Plex Discover watchlist as canonical hub.

Covers the new bidirectional Plex Discover <-> Simkl plan-to-watch sync
(simkl_utils.sync_watchlist_plex_simkl) and the app wiring that replaces the
old "not supported" path.
"""

import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

_TMP = tempfile.mkdtemp(prefix="plexytrack_wh_")
os.environ.setdefault("PLEXYTRACK_CONFIG_DIR", os.path.join(_TMP, "config"))
os.environ.setdefault("PLEXYTRACK_STATE_DIR", os.path.join(_TMP, "state"))
os.makedirs(os.environ["PLEXYTRACK_CONFIG_DIR"], exist_ok=True)
os.makedirs(os.environ["PLEXYTRACK_STATE_DIR"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import simkl_utils as su  # noqa: E402

FH = {"simkl-api-key": "k"}


def _plex_item(title, item_type, guid_id, year=2020):
    it = MagicMock()
    it.title = title
    it.type = item_type
    it.year = year
    it.guids = [SimpleNamespace(id=guid_id)]
    return it


class TestWatchlistPlexSimkl:
    def test_bidirectional_add(self, monkeypatch):
        # Plex has movie A; Simkl plan-to-watch has movie B.
        plex_movie = _plex_item("A", "movie", "imdb://ttA")
        plex = MagicMock()
        plex.watchlist.return_value = [plex_movie]
        account = MagicMock()
        plex.myPlexAccount.return_value = account

        monkeypatch.setattr(su, "get_simkl_watchlist", lambda h: {
            "movies": [{"status": "plantowatch", "movie": {"ids": {"imdb": "ttB"}, "title": "B"}}],
            "shows": [],
        })
        added_simkl = {}
        monkeypatch.setattr(su, "add_items_to_simkl_list",
                            lambda h, *, movies=None, shows=None, target_list=None: added_simkl.update(
                                movies=movies, target=target_list))
        # Simkl item B exists in the Plex library -> can be added to Discover.
        lib_item = MagicMock()
        monkeypatch.setattr(su, "find_item_by_guid",
                            lambda plex_, guid: lib_item if guid == "imdb://ttB" else None)

        a_to_simkl, a_to_plex = su.sync_watchlist_plex_simkl(plex, FH)

        # Plex A -> Simkl plan-to-watch
        assert added_simkl["movies"][0]["ids"] == {"imdb": "ttA"}
        assert added_simkl["target"] == "plantowatch"
        assert a_to_simkl == 1
        # Simkl B -> Plex Discover watchlist
        account.addToWatchlist.assert_called_once_with([lib_item])
        assert a_to_plex == 1

    def test_skips_items_present_on_both(self, monkeypatch):
        plex_movie = _plex_item("Same", "movie", "imdb://ttSame")
        plex = MagicMock()
        plex.watchlist.return_value = [plex_movie]
        account = MagicMock()
        plex.myPlexAccount.return_value = account

        monkeypatch.setattr(su, "get_simkl_watchlist", lambda h: {
            "movies": [{"status": "plantowatch", "movie": {"ids": {"imdb": "ttSame"}}}],
            "shows": [],
        })
        added = []
        monkeypatch.setattr(su, "add_items_to_simkl_list", lambda *a, **k: added.append(1))
        monkeypatch.setattr(su, "find_item_by_guid", lambda p, g: None)

        a_to_simkl, a_to_plex = su.sync_watchlist_plex_simkl(plex, FH)
        assert a_to_simkl == 0 and a_to_plex == 0
        assert added == []
        account.addToWatchlist.assert_not_called()

    def test_direction_plex_to_service_only(self, monkeypatch):
        plex_movie = _plex_item("A", "movie", "imdb://ttA")
        plex = MagicMock()
        plex.watchlist.return_value = [plex_movie]
        account = MagicMock()
        plex.myPlexAccount.return_value = account
        monkeypatch.setattr(su, "get_simkl_watchlist", lambda h: {
            "movies": [{"status": "plantowatch", "movie": {"ids": {"imdb": "ttB"}}}], "shows": []})
        monkeypatch.setattr(su, "add_items_to_simkl_list", lambda *a, **k: None)
        monkeypatch.setattr(su, "find_item_by_guid", lambda p, g: MagicMock())

        su.sync_watchlist_plex_simkl(plex, FH, direction="plex_to_service")
        account.addToWatchlist.assert_not_called()

    def test_ignores_non_plantowatch(self, monkeypatch):
        plex = MagicMock()
        plex.watchlist.return_value = []
        plex.myPlexAccount.return_value = MagicMock()
        monkeypatch.setattr(su, "get_simkl_watchlist", lambda h: {
            "movies": [{"status": "completed", "movie": {"ids": {"imdb": "ttDone"}}}], "shows": []})
        called = []
        monkeypatch.setattr(su, "add_items_to_simkl_list", lambda *a, **k: called.append(1))
        monkeypatch.setattr(su, "find_item_by_guid", lambda p, g: called.append("find"))

        a_to_simkl, a_to_plex = su.sync_watchlist_plex_simkl(plex, FH)
        assert (a_to_simkl, a_to_plex) == (0, 0)


class TestWiring:
    def test_sync_inner_wires_simkl_watchlist(self):
        import app
        import inspect
        src = inspect.getsource(app._sync_inner)
        assert "sync_watchlist_plex_simkl" in src
        assert "Watchlist sync with Simkl is not yet supported" not in src
