"""MRTG HTML discovery and numeric statistics; never reads image pixels."""

import math
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from app.connectors.policy import canonical_origin

WINDOWS = {"daily": "d", "weekly": "w", "monthly": "m", "yearly": "y"}
STATS = {"cu": "current", "av": "average", "max": "maximum", "avmx": "average_peak"}


def _allowed_detail(index: str, href: str) -> str | None:
    if len(href) > 2048 or any(ord(c) < 33 for c in href) or any(c in href for c in ("\\", "%")):
        return None
    source = urlsplit(index)
    directory = (
        source.path.rsplit("/", 1)[0] + "/"
        if source.path.lower().endswith((".htm", ".html"))
        else source.path.rstrip("/") + "/"
    )
    base = urlunsplit((source.scheme, source.netloc, directory, "", ""))
    target = urlsplit(urljoin(base, href))
    if (
        canonical_origin(urlunsplit((target.scheme, target.netloc, "", "", "")))
        != canonical_origin(urlunsplit((source.scheme, source.netloc, "", "", "")))
        or target.query
        or target.username
        or target.password
    ):
        return None
    if not target.path.startswith(directory) or not re.fullmatch(
        r"[A-Za-z0-9_./-]+\.html?", target.path, re.I
    ):
        return None
    if any(part in {".", ".."} for part in target.path.split("/")):
        return None
    resolved = urlunsplit((source.scheme, source.netloc, target.path, "", ""))
    return resolved if len(resolved) <= 2048 else None


def allowed_detail(index: str, href: str) -> str | None:
    try:
        return _allowed_detail(index, href)
    except ValueError:
        return None


class Index(HTMLParser):
    def __init__(self):
        super().__init__()
        self.href = None
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.href = attrs.get("href")
        elif tag == "img" and self.href:
            self.links.append(self.href)

    def handle_endtag(self, tag):
        if tag == "a":
            self.href = None


def discover(index: str, body: str) -> list[str]:
    parser = Index()
    parser.feed(body)
    urls = list(dict.fromkeys(url for href in parser.links if (url := allowed_detail(index, href))))
    if len(urls) > 100:
        raise ValueError("El índice supera el límite de 100 páginas.")
    if not urls:
        raise ValueError(
            "No se encontraron páginas de detalle autorizadas enlazadas desde imágenes."
        )
    return urls


def numeric(text: str):
    match = re.match(r"^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*(.*?)\s*$", text)
    if not match:
        return None
    value = float(match[1])
    return (value, match[2]) if math.isfinite(value) else None


class Detail(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}
        self.window = None
        self.heading = None
        self.title = ""
        self.in_title = False
        self.hidden = False
        self.text = []
        self.row = None
        self.cell = None
        self.channel = None
        self.columns = None
        self.closed = False

    def handle_comment(self, data):
        match = re.fullmatch(r"\s*(avmx|cu|av|max)(in|out)\s+([dwmy])\s+(.+?)\s*", data)
        if match and (number := numeric(match[4])) and not number[1]:
            key = (match[3], match[2], STATS[match[1]])
            self.values[key] = {
                "value": number[0],
                "source": "comment",
                "source_unit": None,
                "label": match[2],
            }

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"script", "style"}:
            self.hidden = True
        if tag == "title":
            self.in_title = True
        if tag == "h2":
            self.heading = ""
        if tag == "table":
            self.columns = None
        if tag == "tr":
            self.row = []
            self.channel = next(
                (c for c in attrs.get("class", "").split() if c in {"in", "out"}), None
            )
        if tag in {"td", "th"} and self.row is not None:
            self.cell = ""

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
        if self.in_title:
            self.title += data
        if self.heading is not None:
            self.heading += data
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = False
        if tag == "title":
            self.in_title = False
        if tag == "h2" and self.heading is not None:
            self.window = next(
                (short for name, short in WINDOWS.items() if name in self.heading.lower()), None
            )
            self.heading = None
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append(" ".join(self.cell.split()))
            self.cell = None
        if tag == "tr" and self.row is not None:
            lowered = [x.lower() for x in self.row]
            if {"max", "average", "current"} <= set(lowered):
                self.columns = lowered
            elif self.columns and self.window and len(self.row) == len(self.columns):
                channel = self.channel or {"in": "in", "out": "out"}.get(lowered[0])
                if channel:
                    for column, content in zip(self.columns, self.row, strict=True):
                        if column in {"max", "average", "current"} and (number := numeric(content)):
                            key = (self.window, channel, "maximum" if column == "max" else column)
                            self.values.setdefault(
                                key,
                                {
                                    "value": number[0],
                                    "source": "table",
                                    "source_unit": number[1][:80],
                                    "label": self.row[0][:120],
                                },
                            )
            self.row = None
        if tag == "table":
            self.columns = None
        if tag == "html":
            self.closed = True


def parse_detail(
    body: str, timezone: str | None = None, observed_at: datetime | None = None
) -> dict:
    parser = Detail()
    parser.feed(body)
    if not parser.values:
        raise ValueError("La página no contiene estadísticas MRTG reconocibles.")
    warnings = []
    text = " ".join(" ".join(parser.text).split())
    match = re.search(
        r"last updated\s+([A-Za-z]+,\s+\d{1,2}\s+[A-Za-z]+\s+\d{4}\s+at\s+\d{1,2}:\d{2})",
        text,
        re.I,
    )
    source_text = match[1] if match else None
    source_at = None
    if source_text and timezone:
        try:
            naive = datetime.strptime(source_text, "%A, %d %B %Y at %H:%M")
            zone = ZoneInfo(timezone)
            # Ambiguous/nonexistent wall times must not silently pick a DST fold.
            first, second = naive.replace(tzinfo=zone, fold=0), naive.replace(tzinfo=zone, fold=1)
            if (
                first.utcoffset() != second.utcoffset()
                or first.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != naive
            ):
                raise ValueError("Ambiguous local time")
            source_at = first.astimezone(UTC)
        except ValueError:
            warnings.append("Fecha de origen no interpretable o ambigua por cambio horario.")
    if source_at is None:
        warnings.append("Frescura de origen sin verificar: falta fecha o zona horaria.")
    elif observed_at:
        age = (observed_at - source_at).total_seconds()
        if age > 900:
            warnings.append("La página MRTG lleva más de 15 minutos sin actualizarse.")
        elif age < -300:
            warnings.append("La fecha de origen está en el futuro; revisa reloj y zona horaria.")
    if not parser.closed:
        warnings.append("Documento HTML incompleto.")
    values = [dict(window=w, channel=c, statistic=s, **v) for (w, c, s), v in parser.values.items()]
    return {
        "title": parser.title.strip()[:200],
        "values": values,
        "source_time_text": source_text,
        "source_at": source_at,
        "warnings": warnings,
    }
