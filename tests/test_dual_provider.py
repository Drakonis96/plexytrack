"""Tests for connection #1: simultaneous dual-provider sync (Plex -> Trakt AND Simkl).

These exercise the orchestration added to app.py:
- _resolve_dual_providers(): which providers run based on available tokens.
- _sync_dual(): freezes the Plex window, runs one pass per provider, advances
  the window once at the end, and isolates per-provider failures.
- sync(): dispatches to _sync_dual only when SYNC_PROVIDER == "both".
"""

import os
import sys
import tempfile

# app.py needs the config/state dirs to exist at import time.
_TMP = tempfile.mkdtemp(prefix="plexytrack_test_")
os.environ.setdefault("PLEXYTRACK_CONFIG_DIR", os.path.join(_TMP, "config"))
os.environ.setdefault("PLEXYTRACK_STATE_DIR", os.path.join(_TMP, "state"))
os.makedirs(os.environ["PLEXYTRACK_CONFIG_DIR"], exist_ok=True)
os.makedirs(os.environ["PLEXYTRACK_STATE_DIR"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402


class TestResolveDualProviders:
    def test_both_tokens_present(self, monkeypatch):
        monkeypatch.setattr("app.load_trakt_tokens", lambda: True)
        monkeypatch.setattr("app.load_simkl_tokens", lambda: True)
        monkeypatch.setenv("TRAKT_ACCESS_TOKEN", "t")
        monkeypatch.setenv("SIMKL_ACCESS_TOKEN", "s")
        assert app._resolve_dual_providers() == ["trakt", "simkl"]

    def test_only_trakt_token(self, monkeypatch):
        monkeypatch.setattr("app.load_trakt_tokens", lambda: True)
        monkeypatch.setattr("app.load_simkl_tokens", lambda: False)
        monkeypatch.setenv("TRAKT_ACCESS_TOKEN", "t")
        monkeypatch.delenv("SIMKL_ACCESS_TOKEN", raising=False)
        assert app._resolve_dual_providers() == ["trakt"]

    def test_no_tokens(self, monkeypatch):
        monkeypatch.setattr("app.load_trakt_tokens", lambda: False)
        monkeypatch.setattr("app.load_simkl_tokens", lambda: False)
        monkeypatch.delenv("TRAKT_ACCESS_TOKEN", raising=False)
        monkeypatch.delenv("SIMKL_ACCESS_TOKEN", raising=False)
        assert app._resolve_dual_providers() == []


class TestSyncDual:
    def test_runs_each_provider_with_frozen_window(self, monkeypatch):
        calls = []
        saved = []
        monkeypatch.setattr("app._resolve_dual_providers", lambda: ["trakt", "simkl"])
        monkeypatch.setattr("app.load_last_plex_sync", lambda: "2025-01-01T00:00:00Z")
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: saved.append(ts))
        monkeypatch.setattr("app.SYNC_WATCHED", True)

        def fake_inner(provider=None, shared_last_sync=None, defer_save=False):
            calls.append((provider, shared_last_sync, defer_save))

        monkeypatch.setattr("app._sync_inner", fake_inner)
        app.stop_event.clear()

        app._sync_dual()

        assert [c[0] for c in calls] == ["trakt", "simkl"]
        # Same frozen window for both, and save deferred inside each pass.
        assert all(c[1] == "2025-01-01T00:00:00Z" for c in calls)
        assert all(c[2] is True for c in calls)
        # Window advanced exactly once, after both passes.
        assert len(saved) == 1

    def test_no_save_when_watched_disabled(self, monkeypatch):
        saved = []
        monkeypatch.setattr("app._resolve_dual_providers", lambda: ["trakt"])
        monkeypatch.setattr("app.load_last_plex_sync", lambda: None)
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: saved.append(ts))
        monkeypatch.setattr("app.SYNC_WATCHED", False)
        monkeypatch.setattr("app._sync_inner", lambda **k: None)
        app.stop_event.clear()

        app._sync_dual()
        assert saved == []

    def test_no_providers_does_nothing(self, monkeypatch):
        ran = []
        saved = []
        monkeypatch.setattr("app._resolve_dual_providers", lambda: [])
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: saved.append(ts))
        monkeypatch.setattr("app._sync_inner", lambda **k: ran.append(1))

        app._sync_dual()
        assert ran == []
        assert saved == []

    def test_provider_failure_isolated(self, monkeypatch):
        ran = []
        monkeypatch.setattr("app._resolve_dual_providers", lambda: ["trakt", "simkl"])
        monkeypatch.setattr("app.load_last_plex_sync", lambda: None)
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: None)
        monkeypatch.setattr("app.SYNC_WATCHED", False)

        def fake_inner(provider=None, shared_last_sync=None, defer_save=False):
            ran.append(provider)
            if provider == "trakt":
                raise RuntimeError("boom")

        monkeypatch.setattr("app._sync_inner", fake_inner)
        app.stop_event.clear()

        app._sync_dual()  # must not raise
        assert ran == ["trakt", "simkl"]


class TestSyncDispatch:
    def test_dispatches_to_dual_when_both(self, monkeypatch):
        called = []
        monkeypatch.setattr("app.SYNC_PROVIDER", "both")
        monkeypatch.setattr("app._sync_dual", lambda: called.append("dual"))
        monkeypatch.setattr("app._sync_inner", lambda *a, **k: called.append("single"))
        app.stop_event.clear()
        app.sync()
        assert called == ["dual"]

    def test_dispatches_to_single_otherwise(self, monkeypatch):
        called = []
        monkeypatch.setattr("app.SYNC_PROVIDER", "trakt")
        monkeypatch.setattr("app._sync_dual", lambda: called.append("dual"))
        monkeypatch.setattr("app._sync_inner", lambda *a, **k: called.append("single"))
        app.stop_event.clear()
        app.sync()
        assert called == ["single"]


class TestCrossServiceBridgeWiring:
    def test_provider_headers_trakt(self, monkeypatch):
        monkeypatch.setenv("TRAKT_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("TRAKT_CLIENT_ID", "cid")
        h = app._provider_headers("trakt")
        assert h["Authorization"] == "Bearer tok"
        assert h["trakt-api-key"] == "cid"
        assert h["trakt-api-version"] == "2"

    def test_provider_headers_none_without_token(self, monkeypatch):
        monkeypatch.delenv("SIMKL_ACCESS_TOKEN", raising=False)
        monkeypatch.setenv("SIMKL_CLIENT_ID", "cid")
        assert app._provider_headers("simkl") is None

    def test_bridge_runs_with_toggles(self, monkeypatch):
        monkeypatch.setattr("app._provider_headers", lambda p: {"h": p})
        monkeypatch.setattr("app.SYNC_RATINGS", True)
        monkeypatch.setattr("app.SYNC_WATCHLISTS", False)
        monkeypatch.setattr("app.SYNC_WATCHED", True)
        captured = {}

        def fake_bridge(th, sh, *, ratings, watchlist, history, **kw):
            captured.update(ratings=ratings, watchlist=watchlist, history=history)
            return {"ratings": 0}

        import bridge_utils
        monkeypatch.setattr(bridge_utils, "run_trakt_simkl_bridge", fake_bridge)
        app._run_cross_service_bridge()
        assert captured == {"ratings": True, "watchlist": False, "history": True}

    def test_bridge_skipped_when_missing_headers(self, monkeypatch):
        monkeypatch.setattr("app._provider_headers", lambda p: None if p == "simkl" else {"h": p})
        ran = []
        import bridge_utils
        monkeypatch.setattr(bridge_utils, "run_trakt_simkl_bridge", lambda *a, **k: ran.append(1))
        app._run_cross_service_bridge()
        assert ran == []

    def test_sync_dual_invokes_bridge_when_both(self, monkeypatch):
        monkeypatch.setattr("app._resolve_dual_providers", lambda: ["trakt", "simkl"])
        monkeypatch.setattr("app.load_last_plex_sync", lambda: None)
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: None)
        monkeypatch.setattr("app.SYNC_WATCHED", False)
        monkeypatch.setattr("app._sync_inner", lambda **k: None)
        called = []
        monkeypatch.setattr("app._run_cross_service_bridge", lambda: called.append(1))
        app.stop_event.clear()
        app._sync_dual()
        assert called == [1]

    def test_sync_dual_skips_bridge_when_single(self, monkeypatch):
        monkeypatch.setattr("app._resolve_dual_providers", lambda: ["trakt"])
        monkeypatch.setattr("app.load_last_plex_sync", lambda: None)
        monkeypatch.setattr("app.save_last_plex_sync", lambda ts: None)
        monkeypatch.setattr("app.SYNC_WATCHED", False)
        monkeypatch.setattr("app._sync_inner", lambda **k: None)
        called = []
        monkeypatch.setattr("app._run_cross_service_bridge", lambda: called.append(1))
        app.stop_event.clear()
        app._sync_dual()
        assert called == []


class TestSyncInnerProviderOverride:
    def test_active_provider_defaults_to_global(self, monkeypatch):
        """provider=None must fall back to the global SYNC_PROVIDER."""
        import inspect
        src = inspect.getsource(app._sync_inner)
        assert "active_provider = provider if provider is not None else SYNC_PROVIDER" in src
        # And no stray global references remain inside the function body.
        body = src.split("\n", 1)[1]
        assert "SYNC_PROVIDER" in src  # the fallback line references it
        assert body.count("SYNC_PROVIDER") == 1  # only the fallback line
