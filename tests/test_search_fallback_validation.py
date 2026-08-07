"""Regression tests for the title-search fallback in simkl_search_ids() and
trakt_search_ids() (used when a direct Plex GUID lookup fails).

Both used to accept the search API's #1 result with no sanity check. Real
case: syncing the show "Harlan Coben's Lazarus" (no usable GUID) fell back
to a Simkl title search whose top hit was an unrelated 2025 movie just
called "Lazarus", which then got written to watch history. These tests pin
the fix: reject that case, keep accepting genuine near-matches.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import is_confident_title_match
from simkl_utils import simkl_search_ids
from trakt_utils import trakt_search_ids


def _mock_response(json_data):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = json_data
    return resp


class TestIsConfidentTitleMatch:
    def test_rejects_unrelated_movie_sharing_a_common_word(self):
        # Real reported case: searching the show "Harlan Coben's Lazarus"
        # must not accept an unrelated movie just called "Lazarus".
        assert not is_confident_title_match("Harlan Coben's Lazarus", "Lazarus")

    def test_rejects_completely_different_titles(self):
        assert not is_confident_title_match("Obsession", "The Man Who Slept")

    def test_accepts_exact_title_match(self):
        assert is_confident_title_match("Split", "Split", query_year=2017, candidate_year=2017)

    def test_accepts_minor_punctuation_difference(self):
        assert is_confident_title_match("Alive", "#Alive")

    def test_accepts_subtitle_containment(self):
        # "The Gentlemen" vs "Gentlemen" - legitimate near-match.
        assert is_confident_title_match("Gentlemen", "The Gentlemen")

    def test_rejects_same_title_far_apart_in_year(self):
        # Same normalized title, but 8 years apart - likely a different
        # production sharing a generic name, not a release-date quirk.
        assert not is_confident_title_match(
            "Split", "Split", query_year=2009, candidate_year=2017
        )

    def test_allows_one_year_release_date_drift(self):
        assert is_confident_title_match(
            "Some Movie", "Some Movie", query_year=2016, candidate_year=2017
        )

    def test_missing_titles_never_match(self):
        assert not is_confident_title_match(None, "Anything")
        assert not is_confident_title_match("Anything", None)
        assert not is_confident_title_match("", "")

    def test_non_latin_titles_compare_instead_of_collapsing(self):
        # Normalization must not strip CJK/Cyrillic characters, or every
        # non-Latin title would become an automatic non-match and the
        # fallback would silently skip those libraries entirely.
        assert is_confident_title_match("기생충", "기생충")
        assert not is_confident_title_match("기생충", "올드보이")

    def test_accent_insensitive(self):
        assert is_confident_title_match("Amelie", "Amélie")


class TestSimklSearchIdsValidation:
    @patch("simkl_utils.simkl_request")
    def test_skips_unrelated_top_result(self, mock_req):
        # Simkl's #1 hit for "Harlan Coben's Lazarus" is an unrelated movie.
        mock_req.return_value = _mock_response(
            [{"title": "Lazarus", "year": 2025, "ids": {"imdb": "tt31186865"}}]
        )
        result = simkl_search_ids({}, "Harlan Coben's Lazarus", is_movie=False)
        assert result == {}

    @patch("simkl_utils.simkl_request")
    def test_falls_through_to_a_confident_candidate(self, mock_req):
        # First candidate is unrelated; second is the real match.
        mock_req.return_value = _mock_response(
            [
                {"title": "Lazarus", "year": 2025, "ids": {"imdb": "tt31186865"}},
                {"title": "Harlan Coben's Lazarus", "year": 2025, "ids": {"imdb": "tt00000000"}},
            ]
        )
        result = simkl_search_ids({}, "Harlan Coben's Lazarus", is_movie=False)
        assert result == {"imdb": "tt00000000"}

    @patch("simkl_utils.simkl_request")
    def test_accepts_confident_movie_match(self, mock_req):
        mock_req.return_value = _mock_response(
            [{"title": "Obsession", "year": 2026, "ids": {"imdb": "tt39365308"}}]
        )
        result = simkl_search_ids({}, "Obsession", is_movie=True, year=2026)
        assert result == {"imdb": "tt39365308"}

    @patch("simkl_utils.simkl_request")
    def test_no_candidates_returns_empty(self, mock_req):
        mock_req.return_value = _mock_response([])
        assert simkl_search_ids({}, "Anything", is_movie=True) == {}


class TestTraktSearchIdsValidation:
    @patch("trakt_utils.trakt_request")
    def test_skips_unrelated_top_result(self, mock_req):
        mock_req.return_value = _mock_response(
            [{"movie": {"title": "Lazarus", "year": 2025, "ids": {"imdb": "tt31186865"}}}]
        )
        result = trakt_search_ids({}, "Harlan Coben's Lazarus", is_movie=True)
        assert result == {}

    @patch("trakt_utils.trakt_request")
    def test_accepts_confident_match(self, mock_req):
        mock_req.return_value = _mock_response(
            [{"movie": {"title": "Obsession", "year": 2026, "ids": {"imdb": "tt39365308"}}}]
        )
        result = trakt_search_ids({}, "Obsession", is_movie=True, year=2026)
        assert result == {"imdb": "tt39365308"}

