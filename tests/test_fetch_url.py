import ssl

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


def test_connection_pins_validated_address(monkeypatch):
    answers = iter([[(0, 0, 0, "", ("93.184.216.34", 443))]])
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *a, **k: next(answers))
    seen = {}

    class _Ctx(ssl.SSLContext):
        def wrap_socket(self, sock, server_hostname=None, **kw):
            seen["sni"] = server_hostname
            return sock

    monkeypatch.setattr(
        tools.socket, "create_connection",
        lambda addr, *a, **k: seen.setdefault("addr", addr) and object(),
    )
    conn = tools._PinnedHTTPSConnection("example.com", 443, context=_Ctx(ssl.PROTOCOL_TLS_CLIENT))
    conn.connect()
    assert seen["addr"] == ("93.184.216.34", 443)
    assert seen["sni"] == "example.com"


def test_connection_rejects_rebound_private_address(monkeypatch):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("169.254.169.254", 443))])
    with pytest.raises(ValueError):
        tools._PinnedHTTPSConnection("example.com", 443).connect()
