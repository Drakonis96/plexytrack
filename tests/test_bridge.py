"""Tests for connection #2: direct Trakt <-> Simkl bridge (bridge_utils.py).

All network access is mocked. Each bridge fetches both sides, diffs by shared
id key, and pushes only the items missing on the target side.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_utils as bu

TH = {"trakt": 1}
SH = {"simkl": 1}


# ---------------------------------------------------------------------------
# Ratings
# ---------------------------------------------------------------------------

class TestBridgeRatings:
    def test_propagates_both_directions(self, monkeypatch):
        # Trakt has movie A; Simkl has show B. Each should go to the other side.
        monkeypatch.setattr(bu, "fetch_trakt_ratings", lambda h: [
            {"type": "movie", "rating": 9, "movie": {"ids": {"imdb": "ttA"}}},
        ])
        monkeypatch.setattr(bu, "fetch_simkl_ratings", lambda h: [
            {"type": "show", "rating": 7, "ids": {"tvdb": 555}},
        ])
        posts = []
        monkeypatch.setattr(bu, "simkl_request", lambda m, p, h, **kw: posts.append(("simkl", p, kw.get("json"))))
        monkeypatch.setattr(bu, "trakt_request", lambda m, p, h, **kw: posts.append(("trakt", p, kw.get("json"))))

        pushed = bu.bridge_ratings(TH, SH)
        assert pushed == 2
        by = {svc: payload for svc, _, payload in posts}
        assert by["simkl"]["movies"][0]["ids"] == {"imdb": "ttA"}
        assert by["simkl"]["movies"][0]["rating"] == 9
        assert by["trakt"]["shows"][0]["ids"] == {"tvdb": 555}
        assert by["trakt"]["shows"][0]["rating"] == 7

    def test_skips_items_present_on_both(self, monkeypatch):
        common = {"type": "movie", "rating": 8}
        monkeypatch.setattr(bu, "fetch_trakt_ratings", lambda h: [
            {"type": "movie", "rating": 8, "movie": {"ids": {"imdb": "ttX"}}},
        ])
        monkeypatch.setattr(bu, "fetch_simkl_ratings", lambda h: [
            {"type": "movie", "rating": 8, "ids": {"imdb": "ttX"}},
        ])
        posts = []
        monkeypatch.setattr(bu, "simkl_request", lambda *a, **k: posts.append(a))
        monkeypatch.setattr(bu, "trakt_request", lambda *a, **k: posts.append(a))
        assert bu.bridge_ratings(TH, SH) == 0
        assert posts == []

    def test_direction_trakt_to_simkl_only(self, monkeypatch):
        monkeypatch.setattr(bu, "fetch_trakt_ratings", lambda h: [
            {"type": "movie", "rating": 9, "movie": {"ids": {"imdb": "ttA"}}},
        ])
        monkeypatch.setattr(bu, "fetch_simkl_ratings", lambda h: [
            {"type": "show", "rating": 7, "ids": {"tvdb": 555}},
        ])
        posts = []
        monkeypatch.setattr(bu, "simkl_request", lambda m, p, h, **kw: posts.append("simkl"))
        monkeypatch.setattr(bu, "trakt_request", lambda m, p, h, **kw: posts.append("trakt"))
        bu.bridge_ratings(TH, SH, direction=bu.BRIDGE_TRAKT_TO_SIMKL)
        assert posts == ["simkl"]


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

class TestBridgeWatchlist:
    def test_propagates_both_directions(self, monkeypatch):
        monkeypatch.setattr(bu, "fetch_trakt_watchlist", lambda h: {
            "movies": [{"movie": {"ids": {"imdb": "ttM"}, "title": "M", "year": 2020}}],
            "shows": [],
        })
        monkeypatch.setattr(bu, "get_simkl_watchlist", lambda h: {
            "movies": [],
            "shows": [{"status": "plantowatch", "show": {"ids": {"tvdb": 42}, "title": "S", "year": 2019}}],
        })
        simkl_added = {}
        monkeypatch.setattr(bu, "add_items_to_simkl_list",
                            lambda h, *, movies=None, shows=None, target_list=None: simkl_added.update(
                                movies=movies, shows=shows, target=target_list))
        trakt_posts = []
        monkeypatch.setattr(bu, "trakt_request", lambda m, p, h, **kw: trakt_posts.append((p, kw.get("json"))))

        pushed = bu.bridge_watchlist(TH, SH)
        assert pushed == 2
        # Trakt movie -> Simkl plantowatch
        assert simkl_added["movies"][0]["ids"] == {"imdb": "ttM"}
        assert simkl_added["target"] == "plantowatch"
        # Simkl show -> Trakt watchlist
        assert trakt_posts[0][0] == "/sync/watchlist"
        assert trakt_posts[0][1]["shows"][0]["ids"] == {"tvdb": 42}

    def test_ignores_non_plantowatch_simkl(self, monkeypatch):
        monkeypatch.setattr(bu, "fetch_trakt_watchlist", lambda h: {"movies": [], "shows": []})
        monkeypatch.setattr(bu, "get_simkl_watchlist", lambda h: {
            "movies": [{"status": "completed", "movie": {"ids": {"imdb": "ttDone"}}}],
            "shows": [],
        })
        trakt_posts = []
        monkeypatch.setattr(bu, "add_items_to_simkl_list", lambda *a, **k: trakt_posts.append("simkl"))
        monkeypatch.setattr(bu, "trakt_request", lambda *a, **k: trakt_posts.append("trakt"))
        assert bu.bridge_watchlist(TH, SH) == 0
        assert trakt_posts == []


# ---------------------------------------------------------------------------
# History (movies)
# ---------------------------------------------------------------------------

class TestBridgeHistory:
    def test_propagates_both_directions(self, monkeypatch):
        monkeypatch.setattr(bu, "fetch_trakt_history_full", lambda h: [
            {"type": "movie", "watched_at": "2025-01-01T00:00:00Z", "movie": {"ids": {"imdb": "ttT"}}},
        ])
        # Simkl has a different movie keyed by imdb ttS
        monkeypatch.setattr(bu, "get_simkl_history", lambda h: (
            {"imdb://ttS": ("Simkl Movie", 2021, "2025-02-02T00:00:00Z")},
            {},
        ))
        posts = {}
        monkeypatch.setattr(bu, "simkl_request", lambda m, p, h, **kw: posts.setdefault("simkl", kw.get("json")))
        monkeypatch.setattr(bu, "trakt_request", lambda m, p, h, **kw: posts.setdefault("trakt", kw.get("json")))

        pushed = bu.bridge_history(TH, SH)
        assert pushed == 2
        assert posts["simkl"]["movies"][0]["ids"] == {"imdb": "ttT"}
        assert posts["trakt"]["movies"][0]["ids"] == {"imdb": "ttS"}
        assert posts["trakt"]["movies"][0]["watched_at"] == "2025-02-02T00:00:00Z"

    def test_no_duplicates_when_synced(self, monkeypatch):
        monkeypatch.setattr(bu, "fetch_trakt_history_full", lambda h: [
            {"type": "movie", "watched_at": "2025-01-01T00:00:00Z", "movie": {"ids": {"imdb": "ttSame"}}},
        ])
        monkeypatch.setattr(bu, "get_simkl_history", lambda h: (
            {"imdb://ttSame": ("Same", 2020, "2025-01-01T00:00:00Z")}, {},
        ))
        posts = []
        monkeypatch.setattr(bu, "simkl_request", lambda *a, **k: posts.append("simkl"))
        monkeypatch.setattr(bu, "trakt_request", lambda *a, **k: posts.append("trakt"))
        assert bu.bridge_history(TH, SH) == 0
        assert posts == []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class TestRunBridge:
    def test_runs_enabled_and_isolates_failures(self, monkeypatch):
        monkeypatch.setattr(bu, "bridge_ratings", lambda *a, **k: 3)
        def boom(*a, **k):
            raise RuntimeError("x")
        monkeypatch.setattr(bu, "bridge_watchlist", boom)
        monkeypatch.setattr(bu, "bridge_history", lambda *a, **k: 1)

        result = bu.run_trakt_simkl_bridge(TH, SH)
        assert result["ratings"] == 3
        assert result["history"] == 1
        assert "watchlist" not in result  # failure isolated, key absent

    def test_respects_type_toggles(self, monkeypatch):
        called = []
        monkeypatch.setattr(bu, "bridge_ratings", lambda *a, **k: called.append("r") or 0)
        monkeypatch.setattr(bu, "bridge_watchlist", lambda *a, **k: called.append("w") or 0)
        monkeypatch.setattr(bu, "bridge_history", lambda *a, **k: called.append("h") or 0)
        bu.run_trakt_simkl_bridge(TH, SH, ratings=True, watchlist=False, history=False)
        assert called == ["r"]
