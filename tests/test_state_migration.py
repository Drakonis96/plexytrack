import json
import importlib


def setup_modules(tmp_path, monkeypatch):
    monkeypatch.setenv("PLEXYTRACK_DATA_DIR", str(tmp_path))
    plex_utils = importlib.reload(importlib.import_module("plex_utils"))
    app = importlib.reload(importlib.import_module("app"))
    return plex_utils, app


def test_migrates_v1_state_no_safe_mode(tmp_path, monkeypatch):
    plex_utils, _ = setup_modules(tmp_path, monkeypatch)
    legacy = {"lastSync": "2024-01-01T00:00:00Z", "guid_cache": {"x": "y"}}
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "state.json").write_text(json.dumps(legacy))

    plex_utils.migrate_legacy_state()
    state = plex_utils.load_state()

    assert state["schema"] == 2
    assert state["lastSync"] == legacy["lastSync"]
    assert state["guid_cache"] == legacy["guid_cache"]
    assert not (config_dir / "state.json").exists()

    sync_watched = False
    safe_mode = state.get("lastSync") is None and not sync_watched
    assert not safe_mode


def test_token_refresh_with_migrated_state(tmp_path, monkeypatch):
    plex_utils, app = setup_modules(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAKT_CLIENT_ID", "cid")
    monkeypatch.setenv("TRAKT_CLIENT_SECRET", "secret")
    monkeypatch.setenv("TRAKT_REFRESH_TOKEN", "old")

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "state.json").write_text(json.dumps({"lastSync": "2024-01-01T00:00:00Z"}))

    plex_utils.migrate_legacy_state()

    class DummyResp:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {"access_token": "new", "refresh_token": "new", "expires_in": 3600}

    monkeypatch.setattr(app.requests, "post", lambda *a, **k: DummyResp())
    app.refresh_trakt_token()

    state = plex_utils.load_state()
    sync_watched = False
    safe_mode = state.get("lastSync") is None and not sync_watched
    assert not safe_mode
