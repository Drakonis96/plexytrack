import types

import utils

class DummySection:
    type = "movie"
    def getGuid(self, guid):
        raise Exception("not found")

class DummyAccount:
    def __init__(self, item):
        self.item = item
    def searchDiscover(self, query, limit=1):
        assert query == "tt123"
        return [self.item]

class DummyPlex:
    machineIdentifier = "plex1"
    def __init__(self, item):
        self._item = item
        self.library = types.SimpleNamespace(sections=lambda: [DummySection()])
    def myPlexAccount(self):
        return DummyAccount(self._item)

class DummyItem:
    pass

def test_find_item_by_guid_falls_back_to_discover(monkeypatch):
    utils.reset_sections_cache()
    item = DummyItem()
    plex = DummyPlex(item)
    result = utils.find_item_by_guid(plex, "imdb://tt123")
    assert result is item
