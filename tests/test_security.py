"""
Security hardening tests for PlexyTrack.

Covers:
1. ProxyFix / client-IP configuration for rate limiting.
2. Login brute-force rate limiting.
3. Secure cookie flags (HttpOnly, SameSite, Secure, readable CSRF cookie).
4. CSRF protection on state-changing endpoints.
5. Reinforced password policy on change_password.
6. Forced password change for default admin/admin credentials.
7. Dismissible reinforced-password notice for existing weak passwords.
8. Optional Plex webhook shared-secret token.
"""

import json
import os
import sys

import pytest
from werkzeug.security import generate_password_hash

# Ensure the project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


def _write_creds(path, username="admin", password="admin", *, is_default=None,
                 pw_ack=None):
    data = {
        "username": username,
        "password_hash": generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=16
        ),
    }
    if is_default is not None:
        data["is_default"] = is_default
    if pw_ack is not None:
        data["pw_ack"] = pw_ack
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolate credential storage and reset rate-limit state per test."""
    creds_file = tmp_path / "credentials.json"
    monkeypatch.setattr(app_module, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(app_module, "CREDENTIALS_FILE", str(creds_file))
    app_module._login_attempts.clear()
    app_module.app.testing = True
    return {"tmp_path": tmp_path, "creds_file": str(creds_file)}


@pytest.fixture
def client(env):
    return app_module.app.test_client()


def _authenticate(client, token="test-csrf-token", user="admin",
                  must_change=False, upgrade_notice=False):
    """Put the client into an authenticated session with a known CSRF token."""
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["auth_user"] = user
        sess["_csrf_token"] = token
        if must_change:
            sess["must_change_password"] = True
        if upgrade_notice:
            sess["password_upgrade_notice"] = True


# --------------------------------------------------------------------------- #
# 1. ProxyFix / client IP
# --------------------------------------------------------------------------- #
def test_proxyfix_x_for_matches_trusted_proxy_count():
    assert app_module.app.wsgi_app.x_for == app_module.TRUSTED_PROXY_COUNT


def test_trusted_proxy_count_defaults_to_zero():
    # Default keeps X-Forwarded-For untrusted so a direct instance is not spoofable.
    assert app_module.TRUSTED_PROXY_COUNT == 0


# --------------------------------------------------------------------------- #
# 2. Brute-force rate limiting
# --------------------------------------------------------------------------- #
def test_login_rate_limited_after_five_failures(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse", is_default=False,
                 pw_ack=True)
    for _ in range(5):
        r = client.post("/login", data={"username": "admin", "password": "nope"})
        assert b"Invalid username or password" in r.data
    r = client.post("/login", data={"username": "admin", "password": "nope"})
    assert b"Too many failed attempts" in r.data


def test_successful_login_resets_rate_limit(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse", is_default=False,
                 pw_ack=True)
    for _ in range(3):
        client.post("/login", data={"username": "admin", "password": "nope"})
    # A good login clears the counter.
    r = client.post("/login", data={"username": "admin", "password": "correcthorse"})
    assert r.status_code == 302
    assert app_module._login_attempts.get("127.0.0.1", []) == []


# --------------------------------------------------------------------------- #
# 3. Cookie flags
# --------------------------------------------------------------------------- #
def test_session_cookie_flags_configured():
    cfg = app_module.app.config
    assert cfg["SESSION_COOKIE_HTTPONLY"] is True
    assert cfg["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert cfg["SESSION_COOKIE_SECURE"] == app_module.SECURE_COOKIES


def test_csrf_cookie_published_and_readable(env, client):
    _authenticate(client)
    r = client.get("/api/security/status")
    assert r.status_code == 200
    cookies = r.headers.getlist("Set-Cookie")
    csrf_cookie = [c for c in cookies if c.startswith(app_module.CSRF_COOKIE_NAME + "=")]
    assert csrf_cookie, "CSRF cookie should be set for authenticated responses"
    # Must be readable by JS (no HttpOnly) to be usable as a CSRF header.
    assert "HttpOnly" not in csrf_cookie[0]


# --------------------------------------------------------------------------- #
# 4. CSRF protection
# --------------------------------------------------------------------------- #
def test_mutating_request_without_csrf_token_rejected(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse")
    _authenticate(client)
    r = client.post(
        "/api/change_password",
        json={"username": "admin", "new_password": "abcd1234",
              "confirm_password": "abcd1234"},
    )
    assert r.status_code == 400
    assert r.get_json()["error"] == "CSRF validation failed"


def test_mutating_request_with_csrf_header_accepted(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse")
    _authenticate(client, token="tok123")
    r = client.post(
        "/api/change_password",
        json={"username": "admin", "new_password": "abcd1234",
              "confirm_password": "abcd1234"},
        headers={"X-CSRFToken": "tok123"},
    )
    assert r.status_code == 200
    assert r.get_json()["success"] is True


def test_get_requests_not_csrf_blocked(env, client):
    _authenticate(client)
    r = client.get("/api/security/status")
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# 5. Password policy
# --------------------------------------------------------------------------- #
def test_change_password_rejects_short_password(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse")
    _authenticate(client, token="tok")
    r = client.post(
        "/api/change_password",
        json={"username": "admin", "new_password": "short", "confirm_password": "short"},
        headers={"X-CSRFToken": "tok"},
    )
    assert r.status_code == 400
    assert "at least" in r.get_json()["error"]


def test_change_password_rejects_overlong_password(env, client):
    _write_creds(env["creds_file"], "admin", "correcthorse")
    _authenticate(client, token="tok")
    huge = "a" * (app_module.MAX_PASSWORD_LENGTH + 1)
    r = client.post(
        "/api/change_password",
        json={"username": "admin", "new_password": huge, "confirm_password": huge},
        headers={"X-CSRFToken": "tok"},
    )
    assert r.status_code == 400
    assert "at most" in r.get_json()["error"]


def test_change_password_clears_default_and_ack_flags(env, client):
    _write_creds(env["creds_file"], "admin", "admin", is_default=True)
    _authenticate(client, token="tok", must_change=True)
    r = client.post(
        "/api/change_password",
        json={"username": "admin", "new_password": "brandnewpass", "confirm_password": "brandnewpass"},
        headers={"X-CSRFToken": "tok"},
    )
    assert r.status_code == 200
    saved = json.load(open(env["creds_file"]))
    assert saved["is_default"] is False
    assert saved["pw_ack"] is True
    with client.session_transaction() as sess:
        assert not sess.get("must_change_password")


# --------------------------------------------------------------------------- #
# 6. Forced password change (default admin/admin)
# --------------------------------------------------------------------------- #
def test_default_credentials_force_password_change(env, client):
    _write_creds(env["creds_file"], "admin", "admin", is_default=True)
    r = client.post("/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get("must_change_password") is True
    # Any other page redirects to the forced change page.
    r2 = client.get("/api/security/status")
    # security_status is on the allow-list, so it responds normally...
    assert r2.status_code == 200
    assert r2.get_json()["must_change_password"] is True
    # ...but a normal page is redirected.
    r3 = client.get("/settings")
    assert r3.status_code == 302
    assert "/account/password" in r3.headers["Location"]


def test_forced_change_page_renders(env, client):
    _write_creds(env["creds_file"], "admin", "admin", is_default=True)
    _authenticate(client, must_change=True)
    r = client.get("/account/password")
    assert r.status_code == 200
    assert b"password" in r.data.lower()


# --------------------------------------------------------------------------- #
# 7. Reinforced-password notice for existing weak passwords
# --------------------------------------------------------------------------- #
def test_existing_weak_password_triggers_notice(env, client):
    # Custom (non-default) password that is shorter than the new minimum.
    _write_creds(env["creds_file"], "admin", "weak", is_default=False)
    r = client.post("/login", data={"username": "admin", "password": "weak"})
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get("password_upgrade_notice") is True
        assert not sess.get("must_change_password")


def test_compliant_password_no_notice(env, client):
    _write_creds(env["creds_file"], "admin", "longenoughpw", is_default=False)
    r = client.post("/login", data={"username": "admin", "password": "longenoughpw"})
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert not sess.get("password_upgrade_notice")


def test_acknowledged_password_no_notice(env, client):
    _write_creds(env["creds_file"], "admin", "weak", is_default=False, pw_ack=True)
    r = client.post("/login", data={"username": "admin", "password": "weak"})
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert not sess.get("password_upgrade_notice")


def test_ack_endpoint_persists_and_clears_notice(env, client):
    _write_creds(env["creds_file"], "admin", "weak", is_default=False)
    _authenticate(client, token="tok", upgrade_notice=True)
    r = client.post("/api/security/ack_password", headers={"X-CSRFToken": "tok"})
    assert r.status_code == 200
    saved = json.load(open(env["creds_file"]))
    assert saved["pw_ack"] is True
    with client.session_transaction() as sess:
        assert not sess.get("password_upgrade_notice")


# --------------------------------------------------------------------------- #
# 8. Webhook shared secret
# --------------------------------------------------------------------------- #
def test_webhook_open_when_no_token(env, client, monkeypatch):
    monkeypatch.setattr(app_module, "WEBHOOK_TOKEN", "")
    r = client.post("/webhook", data="{}", content_type="application/json")
    assert r.status_code == 204


def test_webhook_rejects_missing_token(env, client, monkeypatch):
    monkeypatch.setattr(app_module, "WEBHOOK_TOKEN", "s3cret")
    r = client.post("/webhook", data="{}", content_type="application/json")
    assert r.status_code == 403


def test_webhook_accepts_valid_token(env, client, monkeypatch):
    monkeypatch.setattr(app_module, "WEBHOOK_TOKEN", "s3cret")
    r = client.post("/webhook?token=s3cret", data="{}", content_type="application/json")
    assert r.status_code == 204
