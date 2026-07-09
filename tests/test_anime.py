"""Tests for connection #5: cross-service anime matching via Simkl id graph.

Covers is_anime_item, update_simkl_anime (TVDB/TMDB anime-season handling),
resolve_anime_ids (Simkl /redirect id bridge), and the anime-aware bridge key.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import simkl_utils as su
import bridge_utils as bu

FH = {"simkl-api-key": "k"}


def _resp(json_data=None, status_code=200, headers=None, content=b"ok"):
    r = MagicMock()
    r.status_code = status_code
    r.content = content
    r.headers = headers or {}
    r.json.return_value = json_data if json_data is not None else {}
    return r


class TestIsAnime:
    def test_mal_id(self):
        assert su.is_anime_item({"ids": {"mal": 16498}}) is True

    def test_anidb_id(self):
        assert su.is_anime_item({"ids": {"anidb": 9541}}) is True

    def test_anime_type(self):
        assert su.is_anime_item({"anime_type": "tv"}) is True

    def test_regular_show(self):
        assert su.is_anime_item({"ids": {"imdb": "tt0903747", "tvdb": 81189}}) is False

    def test_empty(self):
        assert su.is_anime_item({}) is False
        assert su.is_anime_item(None) is False


class TestUpdateSimklAnime:
    @patch("simkl_utils.simkl_request")
    def test_tvdb_seasons_flag(self, mock_req):
        mock_req.return_value = _resp({"added": {"shows": 1}})
        anime = [{"title": "Attack on Titan", "year": 2013,
                  "ids": {"mal": 16498, "tvdb": 267440},
                  "seasons": [{"number": 1, "episodes": [{"number": 1}]}]}]
        su.update_simkl_anime(FH, anime, use_tvdb_anime_seasons=True)
        payload = mock_req.call_args[1]["json"]
        assert payload["shows"][0]["use_tvdb_anime_seasons"] is True
        assert payload["shows"][0]["title"] == "Attack on Titan"

    @patch("simkl_utils.simkl_request")
    def test_without_flag(self, mock_req):
        mock_req.return_value = _resp({})
        su.update_simkl_anime(FH, [{"title": "Naruto", "ids": {"mal": 20}}], use_tvdb_anime_seasons=False)
        assert "use_tvdb_anime_seasons" not in mock_req.call_args[1]["json"]["shows"][0]

    @patch("simkl_utils.simkl_request")
    def test_empty_no_request(self, mock_req):
        assert su.update_simkl_anime(FH, []) == {}
        mock_req.assert_not_called()

    @patch("simkl_utils.simkl_request")
    def test_status_passthrough(self, mock_req):
        mock_req.return_value = _resp({})
        su.update_simkl_anime(FH, [{"title": "One Piece", "ids": {"mal": 21}, "status": "watching"}])
        assert mock_req.call_args[1]["json"]["shows"][0]["status"] == "watching"


class TestResolveAnimeIds:
    def test_parse_id_from_url(self):
        assert su._parse_simkl_id_from_url("https://simkl.com/anime/12345/attack-on-titan") == "12345"
        assert su._parse_simkl_id_from_url("https://simkl.com/tv/99/x") == "99"
        assert su._parse_simkl_id_from_url("") is None

    @patch("simkl_utils.simkl_request")
    def test_resolves_via_redirect(self, mock_req):
        redirect = _resp(status_code=301, headers={"Location": "https://simkl.com/anime/12345/aot"})
        detail = _resp({"ids": {"mal": 16498, "anidb": 9541, "tvdb": 267440}})
        mock_req.side_effect = [redirect, detail]

        result = su.resolve_anime_ids(FH, {"mal": 16498})
        assert result["tvdb"] == 267440
        assert result["simkl"] == "12345"
        # First call is /redirect with allow_redirects False and the mal param.
        first = mock_req.call_args_list[0]
        assert first[0][1] == "/redirect"
        assert first[1]["params"]["mal"] == 16498
        assert first[1]["allow_redirects"] is False

    @patch("simkl_utils.simkl_request")
    def test_no_ids_returns_empty(self, mock_req):
        assert su.resolve_anime_ids(FH, {}) == {}
        mock_req.assert_not_called()

    @patch("simkl_utils.simkl_request", side_effect=Exception("boom"))
    def test_error_returns_empty(self, mock_req):
        assert su.resolve_anime_ids(FH, {"mal": 1}) == {}


class TestBridgeAnimeKey:
    def test_anidb_key(self):
        assert bu._ids_key({"anidb": 9541}) == "anidb://9541"

    def test_imdb_still_preferred(self):
        assert bu._ids_key({"imdb": "tt1", "anidb": 9541}) == "imdb://tt1"
