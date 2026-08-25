"""Regression tests for large service-to-Plex watched-history imports."""

from types import SimpleNamespace

import plex_utils
import utils


class DummyEpisode:
    def __init__(self, number, counters):
        self.guid = f"plex://episode/{number}"
        self.guids = [SimpleNamespace(id=f"tvdb://{1000 + number}")]
        self.grandparentTitle = "Example Show"
        self.grandparentRatingKey = "show-1"
        self.parentIndex = 1
        self.index = number
        self.isWatched = False
        self.viewCount = 0
        self._counters = counters

    def markWatched(self):
        self._counters["mark_watched"] += 1


class DummyShowSection:
    type = "show"
    title = "TV Shows"

    def __init__(self, episodes, counters):
        self._episodes = episodes
        self._counters = counters

    def all(self, libtype=None):
        assert libtype == "episode"
        self._counters["bulk_episode_queries"] += 1
        return self._episodes

    def get(self, title):
        self._counters["show_queries"] += 1
        raise AssertionError("bulk-indexed episodes must not trigger per-show queries")


class DummyLibrary:
    def __init__(self, section, counters):
        self._section = section
        self._counters = counters

    def sections(self):
        self._counters["section_queries"] += 1
        return [self._section]


def test_update_plex_bulk_indexes_episodes_once(monkeypatch):
    counters = {
        "section_queries": 0,
        "bulk_episode_queries": 0,
        "show_queries": 0,
        "mark_watched": 0,
    }
    library_episodes = [DummyEpisode(number, counters) for number in range(1, 101)]
    section = DummyShowSection(library_episodes, counters)
    plex = SimpleNamespace(library=DummyLibrary(section, counters))
    exact_show = SimpleNamespace(type="show", ratingKey="show-1")
    monkeypatch.setattr(
        plex_utils,
        "find_item_by_guid",
        lambda _plex, guid: exact_show if guid == "tvdb://1" else None,
    )
    service_episodes = {
        (
            "Example Show",
            f"S01E{number:02d}",
            f"tvdb://{1000 + number}"
            if number % 2
            else ("tvdb://1", f"S01E{number:02d}"),
        )
        for number in range(1, 101)
    }

    plex_utils.update_plex(plex, set(), service_episodes)

    assert counters == {
        "section_queries": 1,
        "bulk_episode_queries": 1,
        "show_queries": 0,
        "mark_watched": 100,
    }


class DummyFallbackShow:
    title = "Example Show"
    type = "show"
    ratingKey = "show-1"

    def __init__(self, episodes, counters):
        self._episodes = episodes
        self._counters = counters

    def episodes(self):
        self._counters["show_episode_queries"] += 1
        return self._episodes


class DummyFallbackSection(DummyShowSection):
    def __init__(self, episodes, counters):
        super().__init__(episodes, counters)
        self._show = DummyFallbackShow(episodes, counters)

    def all(self, libtype=None):
        self._counters["bulk_episode_queries"] += 1
        raise RuntimeError("bulk episode lookup unavailable")

    def get(self, title):
        self._counters["show_queries"] += 1
        return self._show


def test_update_plex_fallback_queries_each_show_once(monkeypatch):
    counters = {
        "section_queries": 0,
        "bulk_episode_queries": 0,
        "show_queries": 0,
        "show_episode_queries": 0,
        "mark_watched": 0,
    }
    library_episodes = [DummyEpisode(number, counters) for number in range(1, 101)]
    section = DummyFallbackSection(library_episodes, counters)
    plex = SimpleNamespace(library=DummyLibrary(section, counters))
    monkeypatch.setattr(
        plex_utils,
        "find_item_by_guid",
        lambda _plex, guid: section._show if guid == "tvdb://1" else None,
    )
    service_episodes = {
        ("Example Show", f"S01E{number:02d}", ("tvdb://1", f"S01E{number:02d}"))
        for number in range(1, 101)
    }

    plex_utils.update_plex(plex, set(), service_episodes)

    assert counters == {
        "section_queries": 1,
        "bulk_episode_queries": 1,
        "show_queries": 0,
        "show_episode_queries": 1,
        "mark_watched": 100,
    }


class DummyMovie:
    title = "Already Watched"
    year = 2026
    guid = "plex://movie/1"
    guids = [SimpleNamespace(id="imdb://tt123")]
    isWatched = True
    viewCount = 1

    def markWatched(self):
        raise AssertionError("an already-watched movie must not be marked again")


class DummyMovieSection:
    type = "movie"
    title = "Movies"

    def __init__(self, counters):
        self._counters = counters

    def all(self):
        self._counters["bulk_movie_queries"] += 1
        return [DummyMovie()]

    def search(self, **kwargs):
        self._counters["title_queries"] += 1
        return []


def test_update_plex_treats_is_watched_as_a_property():
    counters = {
        "section_queries": 0,
        "bulk_movie_queries": 0,
        "title_queries": 0,
    }
    section = DummyMovieSection(counters)
    plex = SimpleNamespace(
        machineIdentifier="issue-253-movie-test",
        library=DummyLibrary(section, counters),
    )
    utils.reset_sections_cache()

    plex_utils.update_plex(
        plex,
        {("Already Watched", 2026, "imdb://tt123")},
        set(),
    )

    assert counters == {
        "section_queries": 1,
        "bulk_movie_queries": 1,
        "title_queries": 0,
    }
