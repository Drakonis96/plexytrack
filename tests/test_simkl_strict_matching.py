"""Regression coverage for strict Simkl-to-Plex watched matching."""

from types import SimpleNamespace

import plex_utils


class DummyEpisode:
    type = "episode"
    isWatched = False
    viewCount = 0

    def __init__(self, title, parent_rating_key):
        self.title = title
        self.guid = f"plex://episode/{parent_rating_key}"
        self.guids = []
        self.grandparentTitle = "One Piece"
        self.grandparentRatingKey = parent_rating_key
        self.parentIndex = 1
        self.index = 1
        self.marked = False

    def markWatched(self):
        self.marked = True


class DummyShowSection:
    type = "show"
    title = "TV Shows"

    def __init__(self, episodes):
        self._episodes = episodes

    def all(self, libtype=None):
        assert libtype == "episode"
        return self._episodes


def test_duplicate_show_title_uses_simkl_show_guid(monkeypatch):
    anime_episode = DummyEpisode("Anime episode", "anime")
    live_action_episode = DummyEpisode("Romance Dawn", "live-action")
    plex = SimpleNamespace(
        library=SimpleNamespace(
            sections=lambda: [DummyShowSection([anime_episode, live_action_episode])]
        )
    )
    live_action_show = SimpleNamespace(type="show", ratingKey="live-action")
    monkeypatch.setattr(
        plex_utils,
        "find_item_by_guid",
        lambda _plex, guid: (
            live_action_show if guid == "imdb://tt11737520" else None
        ),
    )

    plex_utils.update_plex(
        plex,
        set(),
        {("One Piece", "S01E01", ("imdb://tt11737520", "S01E01"))},
    )

    assert live_action_episode.marked is True
    assert anime_episode.marked is False


def test_unknown_show_guid_never_falls_back_to_duplicate_title(monkeypatch):
    anime_episode = DummyEpisode("Anime episode", "anime")
    plex = SimpleNamespace(
        library=SimpleNamespace(
            sections=lambda: [DummyShowSection([anime_episode])]
        )
    )
    monkeypatch.setattr(plex_utils, "find_item_by_guid", lambda *_args: None)

    plex_utils.update_plex(
        plex,
        set(),
        {("One Piece", "S01E01", ("imdb://tt11737520", "S01E01"))},
    )

    assert anime_episode.marked is False


def test_unknown_movie_guid_never_falls_back_to_title(monkeypatch):
    class MovieSection:
        type = "movie"

        def search(self, **_kwargs):
            raise AssertionError("strict matching must not search by title")

    plex = SimpleNamespace(
        library=SimpleNamespace(sections=lambda: [MovieSection()])
    )
    monkeypatch.setattr(plex_utils, "find_item_by_guid", lambda *_args: None)

    plex_utils.update_plex(
        plex,
        {("Dune", 2021, "imdb://tt1160419")},
        set(),
    )
