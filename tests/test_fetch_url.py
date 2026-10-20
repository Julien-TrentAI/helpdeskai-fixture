import pytest

from src.agent import tools


@pytest.fixture(autouse=True)
def _allow(monkeypatch):
    monkeypatch.setenv("FETCH_URL_ALLOWED_HOSTS", "example.com")


@pytest.mark.parametrize("url", [
    "http://example.com/",
    "https://evil.com/",
    "https://169.254.169.254/latest/meta-data/",
    "https://127.0.0.1/",
    "https://user:pw@example.com/",
    "file:///etc/passwd",
])
def test_rejects_disallowed(url):
    with pytest.raises(ValueError):
        tools._validate_fetch_url(url)


@pytest.mark.parametrize("ip", ["169.254.169.254", "127.0.0.1", "10.0.0.5", "::1", "::ffff:127.0.0.1"])
def test_rejects_private_resolution(monkeypatch, ip):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", (ip, 443))])
    with pytest.raises(ValueError):
        tools._validate_fetch_url("https://example.com/")


def test_allows_public(monkeypatch):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443))])
    assert tools._validate_fetch_url("https://example.com/x")


def test_redirect_cap():
    assert tools._ValidatingRedirectHandler.max_redirections == 2
