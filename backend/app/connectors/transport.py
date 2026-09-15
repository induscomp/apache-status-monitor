"""Bounded HTTP reads with public DNS answers pinned to the connection."""

import base64
import http.client
import ipaddress
import socket
import ssl
import threading
from urllib.parse import urlsplit

import dns.resolver

from app.config import get_settings
from app.connectors.policy import validate_service_url


class FetchError(ValueError):
    pass


def public_addresses(host: str) -> list[str]:
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        resolver = dns.resolver.Resolver()
        addresses = []
        for kind in ("A", "AAAA"):
            try:
                addresses.extend(
                    ipaddress.ip_address(str(x))
                    for x in resolver.resolve(host, kind, lifetime=3, search=False)
                )
            except dns.resolver.NoAnswer:
                pass
    if not addresses or any(
        not x.is_global
        or x.is_multicast
        or x.is_reserved
        or (x.version == 6 and (x.ipv4_mapped or x.sixtofour or x.teredo))
        for x in addresses
    ):
        raise FetchError("Destino DNS no público o no permitido.")
    return [str(x) for x in addresses]


def fetch(
    url: str,
    credentials: dict | None = None,
    auto: bool = False,
    *,
    authorized_origin: str | None = None,
    allow_http: bool = False,
) -> str:
    settings = get_settings()
    url = validate_service_url(
        url,
        [authorized_origin] if authorized_origin else settings.allowed_monitor_origins,
        [authorized_origin]
        if authorized_origin and allow_http
        else ([] if authorized_origin else settings.allowed_http_origins),
    )
    parsed = urlsplit(url)
    if credentials and parsed.scheme != "https":
        raise FetchError("Las credenciales requieren HTTPS.")
    addresses = public_addresses(parsed.hostname)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    address = addresses[0]
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    conn = http.client.HTTPConnection(parsed.hostname, port, timeout=15)

    # Shutdown interrupts even slow-drip headers/body. The resolver has its own bounded lifetime.
    def interrupt():
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(15, interrupt)
    timer.daemon = True
    timer.start()
    try:
        sock.settimeout(15)
        sock.connect((address, port))
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        conn.sock = sock
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": "Apache-Status-Monitor/0.2",
            "Connection": "close",
        }
        if credentials:
            encoded = base64.b64encode(
                f"{credentials['username']}:{credentials['password']}".encode()
            ).decode()
            headers["Authorization"] = "Basic " + encoded
        conn.request("GET", (parsed.path or "/") + ("?auto" if auto else ""), headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            raise FetchError(f"HTTP {response.status}; no se siguen redirecciones.")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise FetchError("Compresión de respuesta no admitida.")
        maximum = 2 * 1024 * 1024
        length = response.getheader("Content-Length")
        if length and int(length) > maximum:
            raise FetchError("Respuesta superior a 2 MiB.")
        body = bytearray()
        while chunk := response.read1(min(65536, maximum + 1 - len(body))):
            body.extend(chunk)
            if len(body) > maximum:
                raise FetchError("Respuesta superior a 2 MiB.")
        if length and len(body) != int(length):
            raise FetchError("Respuesta HTTP incompleta.")
        charset = response.headers.get_content_charset() or "utf-8"
        return body.decode(charset, errors="replace")
    finally:
        timer.cancel()
        conn.close()
        sock.close()
