from types import SimpleNamespace

import app


def test_webhook_forwarded_to_simkl(monkeypatch):
    app.LIVE_SYNC = True
    app.SYNC_PROVIDER = "simkl"

    monkeypatch.setenv("SIMKL_CLIENT_ID", "cid")
    monkeypatch.setenv("SIMKL_ACCESS_TOKEN", "token")

    called = {}

    def fake_post(url, data=None, headers=None, timeout=None):
        called["url"] = url
        called["data"] = data
        called["headers"] = headers
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(app.requests, "post", fake_post)
    monkeypatch.setattr(app.scheduler, "add_job", lambda *a, **k: None)

    client = app.app.test_client()
    resp = client.post("/webhook", data=b"payload", content_type="application/json")

    assert resp.status_code == 204
    assert called["url"] == "https://api.simkl.com/sync/plex/webhook?client_id=cid&token=token"
    assert called["data"] == b"payload"
    assert called["headers"]["Content-Type"] == "application/json"

