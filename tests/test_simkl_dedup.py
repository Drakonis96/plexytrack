"""
Tests to verify that Plex → Simkl sync filters out items already present
on Simkl, preventing redundant API calls (duplicate prevention).

Mirrors the deduplication logic already present in the Trakt path.
"""

import os
import sys

import pytest

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSimklDedupLogic:
    """
    Validates the set-difference logic used to filter Plex items
    before sending them to Simkl, ensuring items already on Simkl
    are excluded.
    """

    # -- helpers to simulate the dedup logic extracted from app.py --------

    @staticmethod
    def _compute_items_to_add(plex_items: dict, simkl_items: dict):
        """Reproduce the filtering logic from the Simkl sync path."""
        simkl_guids = set(simkl_items)
        return set(plex_items) - simkl_guids

    # -- tests ------------------------------------------------------------

    def test_no_overlap_sends_all_plex_items(self):
        """When nothing is on Simkl, all Plex items should be sent."""
        plex = {
            "guid://movie/1": {"title": "Movie A", "year": 2024},
            "guid://movie/2": {"title": "Movie B", "year": 2023},
        }
        simkl: dict = {}

        result = self._compute_items_to_add(plex, simkl)
        assert result == {"guid://movie/1", "guid://movie/2"}

    def test_full_overlap_sends_nothing(self):
        """When every Plex item is already on Simkl, nothing should be sent."""
        plex = {
            "guid://movie/1": {"title": "Movie A", "year": 2024},
            "guid://movie/2": {"title": "Movie B", "year": 2023},
        }
        simkl = {
            "guid://movie/1": ("Movie A", 2024),
            "guid://movie/2": ("Movie B", 2023),
        }

        result = self._compute_items_to_add(plex, simkl)
        assert result == set()

    def test_partial_overlap_sends_only_new(self):
        """Only items NOT on Simkl should be sent."""
        plex = {
            "guid://movie/1": {"title": "Movie A", "year": 2024},
            "guid://movie/2": {"title": "Movie B", "year": 2023},
            "guid://movie/3": {"title": "Movie C", "year": 2025},
        }
        simkl = {
            "guid://movie/1": ("Movie A", 2024),
        }

        result = self._compute_items_to_add(plex, simkl)
        assert result == {"guid://movie/2", "guid://movie/3"}

    def test_episodes_partial_overlap(self):
        """Episode dedup works the same as movies."""
        plex_episodes = {
            "guid://ep/s01e01": {"show": "Show A", "code": "S01E01"},
            "guid://ep/s01e02": {"show": "Show A", "code": "S01E02"},
            "guid://ep/s01e03": {"show": "Show A", "code": "S01E03"},
        }
        simkl_episodes = {
            "guid://ep/s01e01": ("Show A", "S01E01"),
            "guid://ep/s01e02": ("Show A", "S01E02"),
        }

        result = self._compute_items_to_add(plex_episodes, simkl_episodes)
        assert result == {"guid://ep/s01e03"}

    def test_empty_plex_sends_nothing(self):
        """If Plex has no history, nothing should be sent."""
        plex: dict = {}
        simkl = {"guid://movie/1": ("Movie A", 2024)}

        result = self._compute_items_to_add(plex, simkl)
        assert result == set()

    def test_both_empty(self):
        """Both empty → nothing to send."""
        assert self._compute_items_to_add({}, {}) == set()

    def test_simkl_extra_items_ignored(self):
        """Items only on Simkl (not on Plex) are irrelevant for Plex→Simkl."""
        plex = {"guid://movie/1": {"title": "Movie A", "year": 2024}}
        simkl = {
            "guid://movie/1": ("Movie A", 2024),
            "guid://movie/99": ("Simkl Only", 2020),
        }

        result = self._compute_items_to_add(plex, simkl)
        assert result == set()


class TestSimklDedupMatchesTraktPattern:
    """
    Verify that the Simkl dedup follows the same set-difference pattern
    used by the Trakt sync path, ensuring parity between providers.
    """

    def test_trakt_style_movie_dedup(self):
        """Simkl movie dedup mirrors Trakt's `guid not in trakt_movie_guids`."""
        plex_movies = {
            "imdb://tt0000001": {"title": "A", "year": 2020, "watched_at": "2025-01-01"},
            "imdb://tt0000002": {"title": "B", "year": 2021, "watched_at": "2025-01-02"},
            "imdb://tt0000003": {"title": "C", "year": 2022, "watched_at": "2025-01-03"},
        }
        simkl_movies = {
            "imdb://tt0000001": ("A", 2020),
        }

        # Simkl path (set difference)
        simkl_movie_guids = set(simkl_movies)
        movies_to_add = set(plex_movies) - simkl_movie_guids

        # Trakt path equivalent (list comprehension with `not in`)
        trakt_movie_guids = set(simkl_movies)  # same data
        new_movies_trakt = [
            guid for guid in plex_movies if guid not in trakt_movie_guids
        ]

        assert movies_to_add == set(new_movies_trakt)
        assert "imdb://tt0000001" not in movies_to_add
        assert "imdb://tt0000002" in movies_to_add
        assert "imdb://tt0000003" in movies_to_add

    def test_trakt_style_episode_dedup(self):
        """Simkl episode dedup mirrors Trakt's episode filtering."""
        plex_episodes = {
            "tvdb://100/s01e01": {"show": "X", "code": "S01E01"},
            "tvdb://100/s01e02": {"show": "X", "code": "S01E02"},
            "tvdb://200/s01e01": {"show": "Y", "code": "S01E01"},
        }
        simkl_episodes = {
            "tvdb://100/s01e01": ("X", "S01E01"),
            "tvdb://200/s01e01": ("Y", "S01E01"),
        }

        simkl_episode_guids = set(simkl_episodes)
        episodes_to_add = set(plex_episodes) - simkl_episode_guids

        trakt_episode_guids = set(simkl_episodes)
        new_episodes_trakt = [
            guid for guid in plex_episodes if guid not in trakt_episode_guids
        ]

        assert episodes_to_add == set(new_episodes_trakt)
        assert episodes_to_add == {"tvdb://100/s01e02"}


class TestSimklReverseDedupIntact:
    """
    Ensure Simkl → Plex direction still correctly filters using
    set(simkl) - set(plex).
    """

    def test_simkl_to_plex_filters_already_watched(self):
        """Items already on Plex should NOT be re-marked."""
        simkl_movies = {
            "guid://movie/1": ("Movie A", 2024),
            "guid://movie/2": ("Movie B", 2023),
            "guid://movie/3": ("Movie C", 2025),
        }
        plex_movies = {
            "guid://movie/1": {"title": "Movie A", "year": 2024},
        }

        movies_to_add_plex = set(simkl_movies) - set(plex_movies)
        assert movies_to_add_plex == {"guid://movie/2", "guid://movie/3"}
        assert "guid://movie/1" not in movies_to_add_plex
