"""Tests for utils.find_item_by_guid.

find_item_by_guid was refactored to build a fast GUID -> item index by scanning
the library sections' items (item.guid + item.guids[].id) rather than making a
per-item ``sec.getGuid()`` / Discover API call. This verifies the index-based
lookup finds an item by its external GUID.
"""

from types import SimpleNamespace

import utils


class DummyItem(SimpleNamespace):
    pass


class DummySection:
    type = "movie"

    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class DummyPlex:
    machineIdentifier = "plex-index-test"

    def __init__(self, item):
        self.library = SimpleNamespace(sections=lambda: [DummySection([item])])


def test_find_item_by_guid_uses_guid_index():
    # Clear any cached index so the section scan runs fresh.
    utils._guid_index.clear()
    utils._guid_index_timestamp.clear()

    item = DummyItem(
        title="Test",
        guid="plex://movie/1",
        guids=[SimpleNamespace(id="imdb://tt123")],
    )
    plex = DummyPlex(item)

    assert utils.find_item_by_guid(plex, "imdb://tt123") is item


def test_find_item_by_guid_returns_none_when_absent():
    utils._guid_index.clear()
    utils._guid_index_timestamp.clear()

    item = DummyItem(
        title="Other",
        guid="plex://movie/2",
        guids=[SimpleNamespace(id="imdb://ttOTHER")],
    )
    plex = DummyPlex(item)

    assert utils.find_item_by_guid(plex, "imdb://tt123") is None
