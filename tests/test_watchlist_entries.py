"""Tests for Plex history functions skipping unwatched items."""

from datetime import datetime, timezone
from types import SimpleNamespace

import plex_utils


class MockItem(SimpleNamespace):
    """Simple item with title and year attributes."""


class MockEntry(SimpleNamespace):
    """Simple history entry returned by plexapi."""

    def source(self):  # pragma: no cover - simple passthrough
        return self.item


def test_owner_history_skips_entries_without_viewed_at(monkeypatch):
    """Entries lacking ``viewedAt`` (e.g. watchlist additions) should be ignored."""

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

    account = SimpleNamespace(
        history=lambda mindate=None, maxresults=None: [watched, watchlist],
        server=lambda name: (_ for _ in ()).throw(Exception("no server")),
        resources=lambda: [],
    )

    monkeypatch.setattr(
        plex_utils, "get_cached_movie_guid", lambda title, year, item: f"imdb://{title}"
    )

    movies, episodes = plex_utils.get_owner_plex_history(account)
    assert "imdb://Watched" in movies
    assert "imdb://On Watchlist" not in movies


def test_managed_user_history_skips_entries_without_viewed_at(monkeypatch):
    """Managed user history should also ignore entries without ``viewedAt``."""

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

    plex_server = SimpleNamespace(
        history=lambda accountID=None, mindate=None, maxresults=None, ratingKey=None: [
            watched,
            watchlist,
        ],
        library=SimpleNamespace(sections=lambda: []),
    )

    class MockUser:
        id = 1
        home = True
        username = "user"

    account = SimpleNamespace(
        users=lambda: [MockUser()],
        resource=lambda name: SimpleNamespace(connect=lambda: plex_server),
        resources=lambda: [],
    )

    monkeypatch.setattr(
        plex_utils, "get_cached_movie_guid", lambda title, year, item: f"imdb://{title}"
    )

    movies, episodes = plex_utils.get_managed_user_plex_history(
        account, user_id=1, server_name="srv"
    )
    assert "imdb://Watched" in movies
    assert "imdb://On Watchlist" not in movies

