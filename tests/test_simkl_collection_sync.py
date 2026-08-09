"""Regression coverage for Plex collection sync with Simkl (#248)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import simkl_utils


def _plex_item(title, year, media_type, guid=None):
    guids = [SimpleNamespace(id=guid)] if guid else []
    return SimpleNamespace(
        title=title,
        year=year,
        type=media_type,
        guid=guid,
        guids=guids,
    )


def _section(media_type, items):
    section = MagicMock()
    section.type = media_type
    section.all.return_value = items
    return section


def test_collection_adds_only_titles_missing_from_every_simkl_status(monkeypatch):
    plex = MagicMock()
    plex.library.sections.return_value = [
        _section(
            "movie",
            [
                _plex_item("Already Completed", 2020, "movie", "imdb://tt100"),
                _plex_item("New Movie", 2024, "movie", "tmdb://200"),
            ],
        ),
        _section(
            "show",
            [
                _plex_item("Dropped Show", 2019, "show", "tvdb://300"),
                _plex_item("New Show", 2025, "show"),
            ],
        ),
    ]
    monkeypatch.setattr(
        simkl_utils,
        "get_simkl_watchlist",
        lambda headers: {
            "movies": [
                {
                    "status": "completed",
                    "movie": {
                        "title": "Already Completed",
                        "year": 2020,
                        "ids": {"imdb": "tt100"},
                    },
                }
            ],
            "shows": [
                {
                    "status": "dropped",
                    "show": {
                        "title": "Dropped Show",
                        "year": 2019,
                        "ids": {"tvdb": 300},
                    },
                }
            ],
        },
    )
    captured = {}

    def fake_add(headers, *, movies=None, shows=None, target_list=None):
        captured.update(movies=movies, shows=shows, target_list=target_list)
        return {"added": {"movies": movies or [], "shows": shows or []}}

    monkeypatch.setattr(simkl_utils, "add_items_to_simkl_list", fake_add)

    added = simkl_utils.sync_plex_collection_to_simkl(plex, {"auth": "ok"})

    assert added == 2
    assert captured["target_list"] == "plantowatch"
    assert [item["title"] for item in captured["movies"]] == ["New Movie"]
    assert captured["movies"][0]["ids"] == {"tmdb": 200}
    assert [item["title"] for item in captured["shows"]] == ["New Show"]


def test_collection_batches_writes_and_counts_not_found(monkeypatch):
    plex = MagicMock()
    plex.library.sections.return_value = [
        _section(
            "movie",
            [
                _plex_item("One", 2021, "movie", "tmdb://1"),
                _plex_item("Two", 2022, "movie", "tmdb://2"),
                _plex_item("Three", 2023, "movie", "tmdb://3"),
            ],
        )
    ]
    monkeypatch.setattr(simkl_utils, "get_simkl_watchlist", lambda headers: {})
    responses = [
        {"not_found": {"movies": [{"title": "Two"}]}},
        {"added": {"movies": [{"title": "Three"}]}},
    ]
    batches = []

    def fake_add(headers, *, movies=None, shows=None, target_list=None):
        batches.append(movies)
        return responses.pop(0)

    monkeypatch.setattr(simkl_utils, "add_items_to_simkl_list", fake_add)

    added = simkl_utils.sync_plex_collection_to_simkl(
        plex, {}, batch_size=2
    )

    assert added == 2
    assert [[item["title"] for item in batch] for batch in batches] == [
        ["One", "Two"],
        ["Three"],
    ]


def test_collection_is_a_noop_when_every_title_is_already_tracked(monkeypatch):
    plex = MagicMock()
    plex.library.sections.return_value = [
        _section(
            "movie",
            [_plex_item("Existing", 2020, "movie", "imdb://tt999")],
        )
    ]
    monkeypatch.setattr(
        simkl_utils,
        "get_simkl_watchlist",
        lambda headers: {
            "movies": [
                {
                    "status": "hold",
                    "movie": {
                        "title": "Existing",
                        "year": 2020,
                        "ids": {"imdb": "tt999"},
                    },
                }
            ]
        },
    )
    add = MagicMock()
    monkeypatch.setattr(simkl_utils, "add_items_to_simkl_list", add)

    assert simkl_utils.sync_plex_collection_to_simkl(plex, {}) == 0
    add.assert_not_called()


def test_simkl_collection_control_is_enabled_and_one_way(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "load_trakt_tokens", lambda: False)
    monkeypatch.setattr(app_module, "load_simkl_tokens", lambda: True)
    monkeypatch.setattr(app_module, "load_provider", lambda: None)
    monkeypatch.setattr(app_module, "load_settings", lambda: None)
    monkeypatch.setattr(
        app_module,
        "load_selected_user",
        lambda: {"username": "owner", "role": "owner", "is_owner": True},
    )
    monkeypatch.setattr(app_module, "SYNC_PROVIDER", "simkl")
    monkeypatch.setattr(app_module, "SYNC_COLLECTION", True)

    client = app_module.app.test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True

    response = client.get("/")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="collection" name="collection" checked' in html
    assert "Plex → Simkl Plan to Watch" in html
    assert 'id="collection" name="collection" checked disabled' not in html
