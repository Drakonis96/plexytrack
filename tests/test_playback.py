"""Tests for connection #3: playback progress ("continue watching") between
Plex <-> Trakt <-> Simkl.

Trakt playback functions already have coverage in test_new_features.py; this
file covers the Simkl scrobble lifecycle + playback helpers and the symmetric
Simkl->Plex / Plex->Simkl syncs, plus the app-level wiring/toggle.
"""

import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# app import needs config/state dirs
_TMP = tempfile.mkdtemp(prefix="plexytrack_pb_")
os.environ.setdefault("PLEXYTRACK_CONFIG_DIR", os.path.join(_TMP, "config"))
os.environ.setdefault("PLEXYTRACK_STATE_DIR", os.path.join(_TMP, "state"))
os.makedirs(os.environ["PLEXYTRACK_CONFIG_DIR"], exist_ok=True)
os.makedirs(os.environ["PLEXYTRACK_STATE_DIR"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import simkl_utils as su  # noqa: E402

FH = {"simkl-api-key": "k"}


def _resp(json_data, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    r.content = b"ok"
    r.json.return_value = json_data
    return r


# ---------------------------------------------------------------------------
# Scrobble lifecycle
# ---------------------------------------------------------------------------

class TestScrobblePayload:
    def test_movie_payload(self):
        p = su._build_scrobble_payload(
            {"type": "movie", "title": "Inception", "year": 2010, "ids": {"imdb": "tt1375666"}}, 25.5)
        assert p["progress"] == 25.5
        assert p["movie"]["ids"]["imdb"] == "tt1375666"
        assert "episode" not in p

    def test_episode_payload(self):
        p = su._build_scrobble_payload(
            {"type": "episode", "show_title": "BB", "show_ids": {"tvdb": 81189},
             "season": 1, "episode": 2, "episode_ids": {"tvdb": 42}}, 50.0)
        assert p["episode"]["season"] == 1
        assert p["episode"]["number"] == 2
        assert p["show"]["ids"]["tvdb"] == 81189

    @patch("simkl_utils.simkl_request")
    def test_start_pause_stop_endpoints(self, mock_req):
        mock_req.return_value = _resp({"result": "ok"})
        data = {"type": "movie", "title": "X", "ids": {"imdb": "tt1"}}
        su.simkl_scrobble_start(FH, data, 0.0)
        assert mock_req.call_args[0][1] == "/scrobble/start"
        su.simkl_scrobble_pause(FH, data, 45.0)
        assert mock_req.call_args[0][1] == "/scrobble/pause"
        assert mock_req.call_args[1]["json"]["progress"] == 45.0
        su.simkl_scrobble_stop(FH, data)
        assert mock_req.call_args[0][1] == "/scrobble/stop"
        assert mock_req.call_args[1]["json"]["progress"] == 100.0


# ---------------------------------------------------------------------------
# Playback progress endpoints
# ---------------------------------------------------------------------------

class TestSimklPlayback:
    @patch("simkl_utils.simkl_request")
    def test_get_playback(self, mock_req):
        mock_req.return_value = _resp([{"movie": {"title": "Dune"}, "progress": 45.2}])
        result = su.get_simkl_playback_progress(FH)
        assert result[0]["progress"] == 45.2
        assert mock_req.call_args[0][1] == "/sync/playback"

    @patch("simkl_utils.simkl_request", side_effect=Exception("x"))
    def test_get_playback_error(self, mock_req):
        assert su.get_simkl_playback_progress(FH) == []

    @patch("simkl_utils.simkl_request")
    def test_delete_playback(self, mock_req):
        mock_req.return_value = _resp(None, 204)
        assert su.delete_simkl_playback_item(FH, 12345) is True
        assert mock_req.call_args[0][0] == "DELETE"
        assert "/sync/playback/12345" in mock_req.call_args[0][1]

    @patch("simkl_utils.simkl_request", side_effect=Exception("x"))
    def test_delete_playback_error(self, mock_req):
        assert su.delete_simkl_playback_item(FH, 1) is False

    @patch("simkl_utils.simkl_scrobble_pause")
    @patch("simkl_utils.guid_to_ids", return_value={"tmdb": 438631})
    @patch("simkl_utils.best_guid", return_value="tmdb://438631")
    def test_sync_plex_to_simkl(self, mg, mi, mock_pause):
        plex = MagicMock()
        item = MagicMock()
        item.type = "movie"
        item.title = "Dune"
        item.year = 2021
        item.viewOffset = 3600000
        item.duration = 9000000
        plex.library.onDeck.return_value = [item]
        count = su.sync_plex_playback_to_simkl(plex, FH)
        assert count == 1
        assert 39.0 < mock_pause.call_args[0][2] < 41.0

    def test_sync_plex_to_simkl_empty(self):
        plex = MagicMock()
        plex.library.onDeck.return_value = []
        assert su.sync_plex_playback_to_simkl(plex, FH) == 0

    @patch("simkl_utils.get_simkl_playback_progress")
    @patch("simkl_utils.find_item_by_guid")
    def test_sync_simkl_to_plex_movie(self, mock_find, mock_get):
        mock_get.return_value = [{"movie": {"ids": {"imdb": "tt1"}}, "progress": 50.0}]
        plex_item = MagicMock()
        plex_item.duration = 7200000
        mock_find.return_value = plex_item
        count = su.sync_playback_simkl_to_plex(MagicMock(), FH)
        assert count == 1
        plex_item.updateTimeline.assert_called_once()
        assert plex_item.updateTimeline.call_args[0][0] == 3600000


# ---------------------------------------------------------------------------
# App wiring
# ---------------------------------------------------------------------------

class TestPlaybackWiring:
    def test_settings_roundtrip(self, monkeypatch, tmp_path):
        import app
        monkeypatch.setattr("app.SETTINGS_FILE", str(tmp_path / "settings.json"))
        monkeypatch.setattr("app.SYNC_PLAYBACK", True)
        app.save_settings()
        monkeypatch.setattr("app.SYNC_PLAYBACK", False)
        app.load_settings()
        assert app.SYNC_PLAYBACK is True

    def test_sync_block_references_playback(self):
        import app, inspect
        src = inspect.getsource(app._sync_inner)
        assert "SYNC_PLAYBACK" in src
        assert "sync_playback_plex_to_trakt" in src
        assert "sync_plex_playback_to_simkl" in src
