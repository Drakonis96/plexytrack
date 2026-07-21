# Changelog

## v0.5.4 (2026-07-21)

### Watchlist sync

- **Simkl watchlist-only sync** (#246): the standalone watchlist-only run (the "sync watchlist" job, `trigger=once, mode=watchlist`) no longer bails out with *"Watchlist sync is only supported with Trakt provider."* when Simkl is the selected tracker. The Plex Discover ↔ Simkl plan-to-watch bidirectional sync (already used inside the full sync) is now reachable from the watchlist-only path as well. In **Both** mode the standalone run drives Trakt and Simkl in the same pass. The full-sync Trakt path is unchanged.

## v0.5.3 (2026-07-09)

### Login page

- **Fix invisible logo**: the app logo (`logo.png`) is a white glyph on a transparent background, so it disappeared against the white login card. The `.login-logo` badge now paints the brand accent colour behind it, so the logo renders as a proper blue badge in both light and dark themes.

## v0.5.2 (2026-07-09)

### Logs page

- **Reliable live refresh**: the Logs viewer now polls with cache-busting and the `/api/logs` (and `/api/sync_status`) responses send `no-store` / `X-Accel-Buffering: no` headers, so browser and reverse-proxy caching can no longer freeze the stream. A once-per-second heartbeat shows the line count and "updated Ns ago" so liveness is visible even during quiet periods.
- **Clearer formatting**: log rows now use aligned, colour-coded level badges, zebra striping, row hover and proper message wrapping instead of a cramped single line.

### Sync status accuracy

- A run that aborts early without raising (e.g. a failed Plex connection test, which the pipeline logs instead of raising) is now reported as **error** on the Sync page instead of a misleading *success*.

## v0.5.1 (2026-07-09)

### Observability

- **Live sync status** on the Sync page: shows whether a periodic sync is scheduled, the interval, and when the next run fires (absolute time + countdown). One-off ("Sync Once"), scheduled and webhook-triggered runs now report when they started, when they finished and the outcome (success / error / stopped), with a live status badge.
- **New Logs page**: a read-only, real-time viewer of the application log stream in the sidebar. Logs are colour-coded by level, filterable (Debug/Info/Warning/Error), pausable, and auto-scroll. Backed by an in-memory ring buffer (size configurable via `PLEXYTRACK_LOG_BUFFER`, default 2000 lines) exposed through `/api/logs`; the sync state is exposed through `/api/sync_status`.

## v0.5.0 (2026-07-09)

### New sync connections (Plex ↔ Trakt ↔ Simkl)

- **Delta sync**: uses Trakt `/sync/last_activities` and Simkl `/sync/activities` to skip service → Plex pulls whose category hasn't changed since the last run (fails open, so it never syncs less than before).
- **Dual-provider mode ("Both")**: run the full sync against Trakt **and** Simkl in a single pass, freezing one Plex window across providers.
- **Direct Trakt ↔ Simkl bridge**: mirror ratings, watchlist and movie history straight between the two services.
- **Playback progress ("continue watching")**: mirror in-progress resume points between Plex, Trakt and Simkl (Trakt `/sync/playback` + scrobble, Simkl scrobble + `/sync/playback`).
- **Plex Discover watchlist hub**: bidirectional Plex Discover watchlist ↔ Simkl plan-to-watch, alongside the existing Trakt watchlist sync.
- **Discovery collections**: Trakt recommendations/trending/popular/anticipated and Simkl trending (public CDN) materialized as dynamic Plex collections.
- **Cross-service anime matching** via Simkl's MAL/AniDB id graph; Trakt collection now carries technical metadata and supports shows/episodes.

### Security (public exposure hardening)

- **Security response headers**: Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and HSTS on HTTPS. The `Server` header no longer leaks the Werkzeug version.
- **Request-size limit** (`PLEXYTRACK_MAX_UPLOAD_MB`, default 32) so oversized uploads (e.g. `/backup/restore`) are rejected with 413.
- **Optional Host allowlist** (`PLEXYTRACK_ALLOWED_HOSTS`) to block Host-header spoofing.
- **Production WSGI server**: the container now runs under **waitress** instead of the Werkzeug dev server (`wsgi.py`).
- **Startup security self-check** that warns about weak exposure configuration.

### Logging & housekeeping

- **Improved logging**: module name in the log format and a configurable level via `PLEXYTRACK_LOG_LEVEL`.
- Translated all remaining Spanish code comments to English.
- Documented the default `admin/admin` login and the internet-exposure checklist in the README.

### Tests

- Added test suites for delta sync/Group B, dual provider, the bridge, playback, the watchlist hub, discovery collections and anime matching, plus new security tests. 224 tests passing.

## v0.4.12 (2026-07-09)

### Security

- **CSRF protection**: State-changing requests now require a per-session CSRF token (synchronizer token distributed via a readable cookie, attached automatically to fetch requests and form submissions). The `/login` and Plex `/webhook` endpoints are exempt.
- **Proxy-aware login rate limiting**: `X-Forwarded-For` is only trusted when `PLEXYTRACK_TRUSTED_PROXY_COUNT` > 0, so a directly-exposed instance can no longer be tricked into accepting a spoofed client IP that bypasses the 5-attempts / 5-minutes brute-force limiter. A successful login now clears the counter.
- **Secure cookies**: Session and CSRF cookies can be marked `Secure` via `PLEXYTRACK_SECURE_COOKIES=true` for HTTPS deployments.
- **Reinforced password policy**: The minimum password length is now 8 (configurable via `PLEXYTRACK_MIN_PASSWORD_LENGTH`), with an upper bound to avoid hashing-based denial of service.
- **Default-credential handling**: Signing in with the shipped `admin/admin` login now forces a password change before the app can be used. Existing custom passwords that fall short of the new policy show a dismissible notice offering to change or ignore.
- **Optional webhook secret**: Setting `PLEXYTRACK_WEBHOOK_TOKEN` requires the `/webhook` endpoint to be called with a matching `?token=` (or `X-Webhook-Token` header).

### Tests

- **Added `tests/test_security.py`**: 21 tests covering rate limiting, CSRF enforcement, cookie flags, password policy, the forced/soft password-upgrade flows and the webhook token.

## v0.4.11 (2026-07-07)

### Bug Fixes

- **Fixed Docker Compose startup with missing directory variables**: Compose now falls back to `/config` and `/state` when `PLEXYTRACK_CONFIG_DIR` or `PLEXYTRACK_STATE_DIR` are not set.
- **Hardened startup against empty directory variables**: Empty `PLEXYTRACK_CONFIG_DIR` and `PLEXYTRACK_STATE_DIR` values now fall back to the container defaults instead of crashing on `os.makedirs("")`.

### Documentation

- **Updated Docker Compose directory setup**: The README now documents `PLEXYTRACK_CONFIG_DIR` and `PLEXYTRACK_STATE_DIR` instead of the unused `PLEXYTRACK_DATA_DIR`.

## v0.4.10 (2026-04-20)

### Bug Fixes

- **Fixed incremental Plex history sync in non-UTC timezones**: Naive `viewedAt` datetimes returned by PlexAPI were being stamped as UTC instead of converted from the container's local timezone. This shifted recent watches backwards by the local UTC offset and caused incremental history syncs to return 0 new items after the initial full sync.

### Tests

- **Added regression coverage for naive Plex timestamps**: Added a test that verifies naive local datetimes are converted to the correct UTC timestamp before incremental sync comparisons.

## v0.4.9 (2026-04-05)

### Bug Fixes

- **Fixed Plan to Watch movies being marked as watched in Plex**: The Simkl `/sync/all-items` endpoint returns items from all list statuses (plantowatch, watching, completed, hold, dropped). The sync logic was treating every returned item as watched without checking the status field, causing Plan to Watch, On Hold, and Dropped movies and shows to be incorrectly marked as watched in Plex. Now only items with status `completed` or `watching` are included in the watched history.
- **Fixed incorrect Simkl API field name for list status**: The Simkl API returns the watchlist status in a field called `status` (not `list` as suggested by some API docs). The filter now checks `status` with `list` as a fallback for robustness.
- **Synchronized version strings**: All `APP_VERSION` constants across `app.py`, `simkl_utils.py`, and `trakt_utils.py` are now consistent.

### Maintenance

- **Synced .gitignore and .dockerignore**: Added missing `*.db`, `*.sqlite3`, and `Backup/` entries to `.gitignore`. Removed duplicate `.env` entry from `.dockerignore`.
- **Added comprehensive test suite for plan-to-watch filtering**: 41 tests covering all list statuses, ID types (IMDB, TMDB, TVDB, anidb), full seasons, anime, mixed responses, edge cases, and field name fallback.

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
