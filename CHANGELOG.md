# Changelog

## v0.4.7 (2026-02-24)

### New Features
- **Settings page:** Added a new "Settings" sidebar tab with Security (change password, disconnect services, wipe data) and Redirect URIs management, extracted from the Tracker Login page.

### Changes
- **Tracker Login page:** Simplified to show only service configuration and provider selection (Security and Redirect URIs moved to Settings).
- **Sidebar navigation:** Added "Settings" link with gear icon to all pages.

### Bug Fixes
- **Login screen:** Fixed centering and sizing to match the rest of the app's style (full-width wrapper, larger card and logo).
- **CSS variables:** Fixed undefined `--bg-secondary` (replaced with `--bg-badge`) and `--border` (replaced with `--border-color`) in redirect URI styles.
