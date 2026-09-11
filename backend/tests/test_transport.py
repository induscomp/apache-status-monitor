from email.message import Message

import pytest

from app.connectors import transport


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "224.0.0.1", "::ffff:127.0.0.1"]
)
def test_nonpublic_literal_rejected(host):
    with pytest.raises(transport.FetchError):
        transport.public_addresses(host)


def test_all_dns_answers_validated(monkeypatch):
    monkeypatch.setattr(
        transport.dns.resolver.Resolver,
        "resolve",
        lambda *args, **kwargs: ["93.184.216.34", "127.0.0.1"],
    )
    with pytest.raises(transport.FetchError):
        transport.public_addresses("web.example.test")


@pytest.fixture
def network(monkeypatch):
    events = []

    class Socket:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            events.append(address)

        def close(self):
            pass

        def shutdown(self, how):
            pass

    class Response:
        status = 200
        headers = Message()
        chunks = [b"ok", b""]

        def getheader(self, key, default=None):
            return self.headers.get(key, default)

        def read1(self, size):
            return self.chunks.pop(0)

    response = Response()

    class Connection:
        def __init__(self, host, port, timeout):
            events.append(host)

        def request(self, method, path, headers):
            events.append(path)

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr(transport, "public_addresses", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(transport.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(transport.http.client, "HTTPConnection", Connection)
    return response, events


def test_connection_pins_ip_and_keeps_authority(network):
    response, events = network
    assert transport.fetch("http://metrics.example.test/server-status", auto=True) == "ok"
    assert events == ["metrics.example.test", ("93.184.216.34", 80), "/server-status?auto"]


@pytest.mark.parametrize("case", ["redirect", "oversized", "compressed", "truncated"])
def test_response_boundaries(network, case):
    response, events = network
    if case == "redirect":
        response.status = 302
        response.headers["Location"] = "http://127.0.0.1/private"
    elif case == "oversized":
        response.headers["Content-Length"] = str(2 * 1024 * 1024 + 1)
    elif case == "compressed":
        response.headers["Content-Encoding"] = "gzip"
    else:
        response.headers["Content-Length"] = "100"
    with pytest.raises(transport.FetchError):
        transport.fetch("http://metrics.example.test/server-status")
    assert len(events) == 3


def test_invalid_tls_is_not_bypassed(network, monkeypatch):
    class Context:
        def set_alpn_protocols(self, protocols):
            pass

        def wrap_socket(self, sock, server_hostname):
            assert server_hostname == "web.example.test"
            raise transport.ssl.SSLCertVerificationError("invalid certificate")

    monkeypatch.setattr(transport.ssl, "create_default_context", Context)
    with pytest.raises(transport.ssl.SSLCertVerificationError):
        transport.fetch("https://web.example.test/server-status")
