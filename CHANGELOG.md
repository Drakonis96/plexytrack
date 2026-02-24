# Changelog

## v0.4.6 (2026-02-24)

### New Features

- **Secure Login System**: Added authentication with hashed credentials (PBKDF2-SHA256) for internet-exposed deployments. Default credentials: `admin` / `admin`. Single-user support with rate limiting (5 attempts per 5 minutes) against brute force attacks.
- **Password Change**: New Security tab in the Tracker Login page allows changing the password with username verification and double confirmation. Credentials persist across container restarts and updates via the config volume.
- **Security Tab**: Added a dedicated "Security" tab in the Tracker Login configuration page with:
  - Independent disconnect buttons for Plex, Trakt, and Simkl (removes stored tokens for each service separately).
  - Full data wipe option that removes all tokens, state files, and identifiable data while preserving login credentials.
- **Secure Session Management**: Sessions use HttpOnly cookies with SameSite=Lax policy, 24-hour expiry, and randomly generated secret keys.
- **Redirect URI Management UI**: New "Redirect URIs" tab in the Tracker Login page allows users to add, remove, and select the active OAuth redirect URI for both Trakt and Simkl directly from the web interface. The active URI is persisted in `settings.json` and survives container restarts.
- **Redirect URIs in Docker Compose**: Added `TRAKT_REDIRECT_URI` and `SIMKL_REDIRECT_URI` environment variables with sensible defaults (`http://localhost:5030/oauth/trakt` and `http://localhost:5030/oauth/simkl`) to both `docker-compose.yml` and `docker-compose-local.yml`.

### Changes

- **Logout Behavior**: Logging out now only disconnects from the PlexyTrack session and redirects to the login page. It no longer clears Plex connections, tokens, or synced data.
- **Protected Routes**: All application routes now require authentication. Unauthenticated requests are redirected to the login page (or receive a 401 JSON response for API calls).

### Bug Fixes

- **Plex 401 crash fix**: App no longer hangs/crashes when the Plex token expires during sync. Added `_plex_connection_ok` flag and safety guards to skip bidirectional sync when Plex returns 0 items.
- **Simkl bidirectional sync safety guard**: Added the same safety guard for Simkl provider — prevents unnecessary processing (~41s wasted) when incremental Plex history returns 0 items.
- **`mindate` type error**: Fixed `'str' object has no attribute 'timestamp'` crash when calling `plex_server.history()`. PlexAPI expects a `datetime` object, not an ISO string. Applies to both owner and managed user history functions.
- **OAuth auto-exchange**: Fixed `/oauth/<service>` callback to automatically exchange the authorization code for tokens instead of just displaying it.
- **Plex token persistence**: Plex token is now saved to `auth.json` and loaded on startup, surviving container restarts.
- **Sync concurrency lock**: Added `threading.Lock` to prevent concurrent sync execution. Second sync attempt now logs "Sync already in progress, skipping this run".
- **Race condition with global `plex`**: Captured `sync_plex = plex` local reference at sync start to avoid the global variable being nulled mid-sync.
- **Duplicate sync calls**: Removed duplicate `sync_liked_lists` and `sync_collections_to_trakt` invocations.
- **Unreachable except clause**: Fixed duplicate `except requests.exceptions.RequestException` in `sync_simkl_history`.
- **Account ID warning spam**: Changed Plex `Account` object `id` attribute lookup from WARNING to DEBUG level; added fallback chain (`accountID` → `accountId` → `MyPlexAccount.id`).
- **Silent sync thread crashes**: Added `BaseException` catch with full `traceback` logging in the sync wrapper.

### Performance

- **GUID index optimization**: Replaced per-item `sec.getGuid()` HTTP calls (~2040 requests, 10+ minutes) with a prebuilt GUID index that scans the library once (~1s) and does O(1) dictionary lookups. `sync_liked_lists` went from 10+ minutes to ~2 seconds.

### Improvements

- **Misleading log messages**: Fixed "full sync" log text that appeared during incremental syncs in both Trakt and Simkl code paths.
- **Sync error wrapping**: All post-sync operations (ratings, watchlists, collections, liked lists) are now wrapped in try/except with logging, preventing one failure from blocking subsequent operations.

