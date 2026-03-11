import requests

from app.adp_client import _request_with_retries


class DummyResponse:
    def __init__(self, status_code: int, text: str = "ok"):
        self.status_code = status_code
        self.text = text

    @property
    def ok(self):
        return 200 <= self.status_code < 300


def test_request_with_retries_retries_retryable_status(monkeypatch):
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return DummyResponse(503, "busy")
        return DummyResponse(200, "ok")

    monkeypatch.setattr("app.adp_client.requests.request", fake_request)
    monkeypatch.setattr("app.adp_client.time.sleep", lambda _: None)

    response = _request_with_retries("GET", "https://example.test", action_label="test")
    assert response is not None
    assert response.status_code == 200
    assert calls["count"] == 2


def test_request_with_retries_does_not_retry_non_retryable(monkeypatch):
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        return DummyResponse(400, "bad")

    monkeypatch.setattr("app.adp_client.requests.request", fake_request)
    monkeypatch.setattr("app.adp_client.time.sleep", lambda _: None)

    response = _request_with_retries("GET", "https://example.test", action_label="test")
    assert response is not None
    assert response.status_code == 400
    assert calls["count"] == 1


def test_request_with_retries_stops_after_transport_errors(monkeypatch):
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        raise requests.RequestException("network down")

    monkeypatch.setattr("app.adp_client.requests.request", fake_request)
    monkeypatch.setattr("app.adp_client.time.sleep", lambda _: None)

    response = _request_with_retries(
        "GET",
        "https://example.test",
        action_label="test",
        max_attempts=3,
    )
    assert response is None
    assert calls["count"] == 3
