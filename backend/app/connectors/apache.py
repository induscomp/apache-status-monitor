"""Apache observations: worker counters are never attributed to the last vhost."""

import ipaddress
import math
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urlsplit


class StatusTable(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.row = None
        self.cell = None
        self.closed = False
        self.tables = []
        self.table_number = 0

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.table_number += 1
            self.tables.append(self.table_number)
        elif tag == "tr":
            self.row = []
        elif tag in {"td", "th"} and self.row is not None:
            self.cell = ""

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append(" ".join(self.cell.split()))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.rows.append((self.tables[-1] if self.tables else None, self.row))
            self.row = None
        elif tag == "table" and self.tables:
            self.tables.pop()
        elif tag == "html":
            self.closed = True


def number(value):
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except ValueError, TypeError:
        return None


def parse_auto(body: str) -> dict:
    allowed = {
        "Total Accesses",
        "Total kBytes",
        "Uptime",
        "BusyWorkers",
        "IdleWorkers",
        "ReqPerSec",
        "BytesPerSec",
        "BytesPerReq",
        "CPULoad",
    }
    result = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep and key in allowed and (n := number(value.strip())) is not None:
            result[key] = n
    if not result:
        raise ValueError("No se reconocen métricas de Apache en ?auto.")
    return result


def parse_html(body: str) -> dict:
    parser = StatusTable()
    parser.feed(body)
    parser.close()
    columns = None
    workers = []
    warnings = []
    worker_table = None
    for table, row in parser.rows:
        if columns is not None and table != worker_table:
            continue
        if "Srv" in row and "M" in row:
            columns = row
            worker_table = table
            if not {"Client", "VHost", "Request", "SS", "Req"} <= set(row):
                warnings.append("Faltan columnas detalladas; cobertura parcial.")
            continue
        if columns is None or not row:
            continue
        if len(row) != len(columns):
            warnings.append("Filas incompletas o no reconocidas.")
            continue
        data = dict(zip(columns, row, strict=True))
        if data.get("M") not in {"_", "S", "R", "W", "K", "D", "C", "L", "G", "I", "."}:
            continue
        client = data.get("Client", "")
        try:
            client = str(ipaddress.ip_address(client))
        except ValueError:
            client = None
        request = data.get("Request", "").split()
        method, path = None, None
        if len(request) >= 2:
            method = request[0][:20]
            try:
                path = urlsplit(request[1]).path[:2048] or "/"
            except ValueError:
                pass
        domain = data.get("VHost", "").lower()
        if domain in {"", "-", "(unavailable)"}:
            domain = None
        elif ":" in domain and domain.rsplit(":", 1)[1].isdigit():
            domain = domain.rsplit(":", 1)[0]
        workers.append(
            {
                "slot": data.get("Srv"),
                "state": data["M"],
                "client": client,
                "domain": domain,
                "method": method,
                "path": path,
                "seconds_since": number(data.get("SS")),
                "request_ms": number(data.get("Req")),
                "observation": "last_request" if data["M"] in {"_", ".", "I"} else "current",
            }
        )
    if columns is None:
        raise ValueError("No se reconoce la tabla de workers de Apache Status.")
    if not parser.closed or parser.row is not None:
        warnings.append("Documento incompleto; la muestra puede estar truncada.")
    states = Counter(w["state"] for w in workers)
    return {
        "workers": workers,
        "metrics": {
            "observed_workers": len(workers),
            "active_workers": sum(w["observation"] == "current" for w in workers),
            "states": dict(states),
        },
        "warnings": list(dict.fromkeys(warnings)),
    }
