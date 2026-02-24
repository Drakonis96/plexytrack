# Changelog

## v0.4.8 (2026-02-24)

### New Features


### Bug Fixes

- **Fixed incremental Plex history scan failing silently**: The `mindate` parameter passed to PlexAPI's `history()` was a string instead of a `datetime` object, causing `'str' object has no attribute 'timestamp'` errors that were silently caught. All 5 `history()` calls in `plex_utils.py` now properly convert the string to a `datetime` before use.
- **Fixed watched status not detected for `markPlayed()` items**: Items marked as watched via `markPlayed()` update `lastViewedAt` but not `updatedAt`. The history fallback logic now uses `lastViewedAt` as the primary fallback timestamp instead of `updatedAt`.
- **Removed 748 lines of triplicate function definitions**: Three duplicate definitions each of `get_trakt_history_basic`, `update_trakt`, and `update_simkl` (plus one extra standalone `update_simkl`) were removed from `app.py`. The app now correctly uses the imported versions from `trakt_utils.py` and `simkl_utils.py`.
- **Fixed safety check blocking incremental bidirectional sync**: The safety condition that prevents syncing when no items are found now only applies to full syncs, not incremental ones where returning few items is expected behavior.
- **Fixed Trakt items missed due to minute-level timestamp truncation**: Trakt truncates `watched_at` to the nearest minute. A 2-minute safety margin is now applied to the `start_at` filter when fetching incremental Trakt history, preventing recently added items from being skipped.
- **Fixed show title substring matching returning wrong show**: `get_show_from_library()` used Plex's `sec.get(title)` which does substring matching — searching for "Evil" returned "Ash vs. Evil Dead". Now prefers exact title matches and falls back to search with exact-match preference. This affected both Trakt and Simkl sync.
- **Removed 232 lines of duplicate Simkl functions from `app.py`**: `simkl_request`, `simkl_search_ids`, `simkl_movie_key`, and `get_simkl_history` were all redefined locally in `app.py`, overriding imports from `simkl_utils.py`. The enhanced `get_simkl_history` (with `/sync/all-items` augmentation for completed movies and episodes) was moved to `simkl_utils.py` and the duplicates removed.
- **Fixed Simkl episode sync re-sending episodes every cycle**: Plex episode keys are episode-level GUIDs (e.g., `"imdb://tt10864014"`), while Simkl episode keys from `/sync/all-items` are show-level tuples (e.g., `("imdb://tt9055008", "S01E03")`). The set difference comparison never matched because strings ≠ tuples. Added a secondary lookup by `(show_title, episode_code)` to correctly detect already-synced episodes in both sync directions.
