"""Tests for Plex history functions skipping unwatched items.

get_owner_plex_history / get_managed_user_plex_history were refactored to fetch
history via the configured Plex server (``app.get_plex_server()``) instead of
``account.history()``. The skip-entries-without-``viewedAt`` behaviour (so
watchlist additions aren't synced as watched) is preserved and verified here.
"""

import os
import sys
import tempfile
from datetime import datetime, timezone
from types import SimpleNamespace

# app import (for get_plex_server patching) needs config/state dirs.
_TMP = tempfile.mkdtemp(prefix="plexytrack_wl_")
os.environ.setdefault("PLEXYTRACK_CONFIG_DIR", os.path.join(_TMP, "config"))
os.environ.setdefault("PLEXYTRACK_STATE_DIR", os.path.join(_TMP, "state"))
os.makedirs(os.environ["PLEXYTRACK_CONFIG_DIR"], exist_ok=True)
os.makedirs(os.environ["PLEXYTRACK_STATE_DIR"], exist_ok=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app  # noqa: E402
import plex_utils  # noqa: E402


class MockItem(SimpleNamespace):
    """Simple item with title and year attributes."""


class MockEntry(SimpleNamespace):
    """Simple history entry returned by plexapi."""

    def source(self):  # pragma: no cover - simple passthrough
        return self.item


def _entries():
    watched = MockEntry(
        type="movie",
        viewedAt=datetime(2024, 1, 1, tzinfo=timezone.utc),
        item=MockItem(title="Watched", year=2024),
    )
    watchlist = MockEntry(
        type="movie",
        viewedAt=None,
        item=MockItem(title="On Watchlist", year=2025),
    )
    return [watched, watchlist]


def test_owner_history_skips_entries_without_viewed_at(monkeypatch):
    entries = _entries()
    plex_server = SimpleNamespace(
        account=lambda: SimpleNamespace(accountID=1),
        history=lambda **kw: entries,
    )
    monkeypatch.setattr(app, "get_plex_server", lambda: plex_server)
    monkeypatch.setattr(
        plex_utils, "get_cached_movie_guid", lambda title, year, item: f"imdb://{title}"
    )

    account = SimpleNamespace(id=1)
    movies, episodes = plex_utils.get_owner_plex_history(account)
    assert "imdb://Watched" in movies
    assert "imdb://On Watchlist" not in movies


def test_managed_user_history_skips_entries_without_viewed_at(monkeypatch):
    entries = _entries()
    plex_server = SimpleNamespace(
        friendlyName="srv",
        history=lambda **kw: entries,
        library=SimpleNamespace(sections=lambda: []),
    )

    class MockUser:
        id = 1
        home = True
        username = "user"
        title = "user"

    account = SimpleNamespace(users=lambda: [MockUser()])
    monkeypatch.setattr(app, "get_plex_server", lambda: plex_server)
    monkeypatch.setattr(
        plex_utils, "get_cached_movie_guid", lambda title, year, item: f"imdb://{title}"
    )

    movies, episodes = plex_utils.get_managed_user_plex_history(
        account, user_id=1, server_name="srv"
    )
    assert "imdb://Watched" in movies
    assert "imdb://On Watchlist" not in movies
