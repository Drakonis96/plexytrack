import trakt_utils
import app


class DummyItem:
    TYPE = "movie"


class DummyAccount:
    def __init__(self):
        self.added = []
        self.removed = []

    def watchlist(self, *args, **kwargs):
        return []

    def addToWatchlist(self, items):
        self.added.extend(items)

    def removeFromWatchlist(self, items):
        self.removed.extend(items)


def test_trakt_watchlist_addition_syncs_to_plex(monkeypatch):
    account = DummyAccount()
    monkeypatch.setattr(app, "get_plex_account", lambda: account)
    monkeypatch.setattr(trakt_utils, "find_item_by_guid", lambda plex, guid: DummyItem() if guid == "imdb://tt123" else None)
    monkeypatch.setattr(trakt_utils, "guid_to_ids", lambda guid: {"imdb": guid.split("://")[1]})
    monkeypatch.setattr(trakt_utils, "load_watchlist_state", lambda: {})
    monkeypatch.setattr(trakt_utils, "save_watchlist_state", lambda state: None)

    removed_from_trakt = []

    def fake_trakt_request(method, path, headers, json=None, params=None):
        class Resp:
            def __init__(self, data):
                self._data = data

            def json(self):  # pragma: no cover - simple helper
                return self._data

        if path == "/sync/activities":
            return Resp({"watchlist": {"updated_at": "now"}})
        if path == "/sync/watchlist/movies":
            return Resp([{"movie": {"ids": {"imdb": "tt123"}}}])
        if path == "/sync/watchlist/shows":
            return Resp([])
        if path == "/sync/watchlist/remove":
            removed_from_trakt.append(json)
            return Resp({})
        if path == "/sync/watchlist":
            return Resp({})
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(trakt_utils, "trakt_request", fake_trakt_request)

    plex = object()

    trakt_utils.sync_watchlist(plex, headers={}, direction="both")

    assert len(account.added) == 1
    assert removed_from_trakt == []


def test_trakt_readd_with_newer_listed_at_wins_over_stale_plex_removal(monkeypatch):
    account = DummyAccount()
    monkeypatch.setattr(app, "get_plex_account", lambda: account)
    monkeypatch.setattr(trakt_utils, "find_item_by_guid", lambda plex, guid: DummyItem() if guid == "imdb://tt123" else None)
    monkeypatch.setattr(trakt_utils, "guid_to_ids", lambda guid: {"imdb": guid.split("://")[1]})
    monkeypatch.setattr(
        trakt_utils,
        "load_watchlist_state",
        lambda: {
            "plex": {"guids": ["imdb://tt123"], "types": {"imdb://tt123": "movie"}},
            "trakt": {
                "movies": ["imdb://tt123"],
                "shows": [],
                "listed_at": {"imdb://tt123": "2026-01-01T00:00:00.000Z"},
            },
        },
    )
    monkeypatch.setattr(trakt_utils, "save_watchlist_state", lambda state: None)
    monkeypatch.setattr(app, "WATCHLIST_CONFLICT_RESOLUTION", "last_wins")
    monkeypatch.setattr(app, "WATCHLIST_REMOVAL_ENABLED", True)

    removed_from_trakt = []

    def fake_trakt_request(method, path, headers, json=None, params=None):
        class Resp:
            def __init__(self, data):
                self._data = data

            def json(self):  # pragma: no cover - simple helper
                return self._data

        if path == "/sync/watchlist/movies":
            return Resp([{"listed_at": "2026-01-02T00:00:00.000Z", "movie": {"ids": {"imdb": "tt123"}}}])
        if path == "/sync/watchlist/shows":
            return Resp([])
        if path == "/sync/watchlist/remove":
            removed_from_trakt.append(json)
            return Resp({})
        if path == "/sync/watchlist":
            return Resp({})
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(trakt_utils, "trakt_request", fake_trakt_request)

    trakt_utils.sync_watchlist(object(), headers={}, direction="both")

    assert len(account.added) == 1
    assert removed_from_trakt == []
