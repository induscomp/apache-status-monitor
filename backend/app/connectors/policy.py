import ipaddress
from urllib.parse import urlsplit, urlunsplit


def canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Expected an HTTP(S) origin without credentials, path or query")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    authority = (
        host if port in {None, 443 if parsed.scheme == "https" else 80} else f"{host}:{port}"
    )
    return f"{parsed.scheme}://{authority}"


def validate_service_url(value: str, allowed: list[str], http_allowed: list[str]) -> str:
    """Configuration validation only; never resolves DNS or opens a connection.

    The collection milestone must separately validate and pin all resolved IPs.
    """
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        raise ValueError("URL contains invalid characters")
    parsed = urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
    ):
        raise ValueError("Use the base URL without credentials, query parameters or fragment")
    origin = canonical_origin(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
    if origin not in allowed:
        raise ValueError("Origin is not authorized by the deployment operator")
    if parsed.scheme == "http" and origin not in http_allowed:
        raise ValueError("HTTP requires an explicit origin exception")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        if parsed.hostname == "localhost" or parsed.hostname.endswith(".localhost"):
            raise ValueError("Loopback destinations are prohibited") from None
    else:
        if not address.is_global:
            raise ValueError("Non-public address literals are prohibited")
    return origin + (parsed.path or "/")


def service_transport_options(service):
    if not service.options.get("authorize_origin", False):
        return {}
    parsed = urlsplit(service.url)
    origin = canonical_origin(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
    return {"authorized_origin": origin, "allow_http": service.options.get("allow_http", False)}
