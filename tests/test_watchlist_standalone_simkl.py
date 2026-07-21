"""Tests for the standalone watchlist-only job across providers (issue #246).

The watchlist-only run (``sync_watchlists_job`` -> ``sync_watchlists_only``
with no pre-initialized clients) used to bail out with
"Watchlist sync is only supported with Trakt provider." whenever the selected
provider was Simkl. These tests lock in that the standalone path now routes to
``sync_watchlist_plex_simkl`` for Simkl and drives both services in ``both``
mode, while a full-sync caller (plex + Trakt headers supplied) still runs only
the Trakt path.
"""

import os
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="plexytrack_wsimkl_")
os.environ.setdefault("PLEXYTRACK_CONFIG_DIR", os.path.join(_TMP, "config"))
os.environ.setdefault("PLEXYTRACK_STATE_DIR", os.path.join(_TMP, "state"))
os.makedirs(os.environ["PLEXYTRACK_CONFIG_DIR"], exist_ok=True)
os.makedirs(os.environ["PLEXYTRACK_STATE_DIR"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402


def _patch_common(monkeypatch, plex_obj):
    """Stub the connection/plumbing helpers so only routing logic is exercised."""
    monkeypatch.setattr("app.load_trakt_tokens", lambda: True)
    monkeypatch.setattr("app.load_simkl_tokens", lambda: True)
    monkeypatch.setattr("app.reset_cache", lambda: None)
    monkeypatch.setattr("app.test_connections", lambda: True)
    monkeypatch.setattr("app.get_plex_server", lambda: plex_obj)
    monkeypatch.setattr("app.refresh_trakt_token", lambda: True)
    monkeypatch.setattr("app.WATCHLISTS_SYNC_DIRECTION", "both", raising=False)


class TestStandaloneSimkl:
    def test_simkl_only_routes_to_simkl_sync(self, monkeypatch):
        plex_obj = object()
        _patch_common(monkeypatch, plex_obj)
        monkeypatch.setattr("app.SYNC_PROVIDER", "simkl", raising=False)
        monkeypatch.setenv("SIMKL_ACCESS_TOKEN", "s-token")
        monkeypatch.setenv("SIMKL_CLIENT_ID", "s-client")

        simkl_calls = []
        monkeypatch.setattr(
            "app.sync_watchlist_plex_simkl",
            lambda plex, headers, *, direction=None: simkl_calls.append((plex, headers, direction)),
        )
        trakt_calls = []
        monkeypatch.setattr("app.sync_watchlist", lambda *a, **k: trakt_calls.append(1))

        app.sync_watchlists_only()

        assert len(simkl_calls) == 1, "Simkl watchlist sync should run for provider=simkl"
        plex_arg, headers_arg, direction_arg = simkl_calls[0]
        assert plex_arg is plex_obj
        assert direction_arg == "both"
        assert headers_arg["simkl-api-key"] == "s-client"
        assert headers_arg["Authorization"] == "Bearer s-token"
        assert trakt_calls == [], "Trakt watchlist sync must not run for provider=simkl"

    def test_simkl_only_without_token_is_skipped(self, monkeypatch):
        plex_obj = object()
        _patch_common(monkeypatch, plex_obj)
        monkeypatch.setattr("app.SYNC_PROVIDER", "simkl", raising=False)
        monkeypatch.delenv("SIMKL_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("SIMKL_CLIENT_ID", raising=False)

        simkl_calls = []
        monkeypatch.setattr(
            "app.sync_watchlist_plex_simkl",
            lambda *a, **k: simkl_calls.append(1),
        )
        app.sync_watchlists_only()
        assert simkl_calls == [], "Missing Simkl credentials should skip the sync, not crash"

    def test_both_runs_trakt_and_simkl(self, monkeypatch):
        plex_obj = object()
        _patch_common(monkeypatch, plex_obj)
        monkeypatch.setattr("app.SYNC_PROVIDER", "both", raising=False)
        monkeypatch.setenv("SIMKL_ACCESS_TOKEN", "s-token")
        monkeypatch.setenv("SIMKL_CLIENT_ID", "s-client")
        monkeypatch.setenv("TRAKT_ACCESS_TOKEN", "t-token")
        monkeypatch.setenv("TRAKT_CLIENT_ID", "t-client")

        trakt_calls = []
        simkl_calls = []
        monkeypatch.setattr("app.sync_watchlist", lambda *a, **k: trakt_calls.append(1))
        monkeypatch.setattr("app.mirror_trakt_watchlist_to_simkl", lambda h: None)
        monkeypatch.setattr(
            "app.sync_watchlist_plex_simkl",
            lambda *a, **k: simkl_calls.append(1),
        )

        app.sync_watchlists_only()

        assert trakt_calls == [1], "Trakt watchlist sync should run in both mode"
        assert simkl_calls == [1], "Simkl watchlist sync should run in both mode"


class TestFullSyncCallerUnchanged:
    def test_supplied_trakt_clients_run_only_trakt(self, monkeypatch):
        monkeypatch.setattr("app.SYNC_PROVIDER", "trakt", raising=False)
        monkeypatch.setattr("app.WATCHLISTS_SYNC_DIRECTION", "both", raising=False)
        trakt_calls = []
        simkl_calls = []
        monkeypatch.setattr("app.sync_watchlist", lambda *a, **k: trakt_calls.append(1))
        monkeypatch.setattr("app.mirror_trakt_watchlist_to_simkl", lambda h: None)
        monkeypatch.setattr("app.sync_watchlist_plex_simkl", lambda *a, **k: simkl_calls.append(1))
        # Ensure the connection plumbing is NOT reached when clients are supplied.
        monkeypatch.setattr("app.test_connections", lambda: (_ for _ in ()).throw(AssertionError("must not init")))

        app.sync_watchlists_only(object(), {"trakt-api-key": "k"}, set(), set())

        assert trakt_calls == [1]
        assert simkl_calls == [], "Full-sync Trakt caller must not trigger the Simkl path here"
