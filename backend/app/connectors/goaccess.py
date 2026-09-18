"""Read embedded GoAccess JSON as data, never execute the report's JavaScript."""

import ipaddress
import json
import math
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

GENERAL = {
    "total_requests",
    "valid_requests",
    "failed_requests",
    "unique_visitors",
    "bandwidth",
    "excluded_hits",
    "unique_not_found",
}


def count(value):
    value = value.get("count") if isinstance(value, dict) else value
    return (
        value
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
        else None
    )


def parse_report(body):
    match = re.search(r"\b(?:var|let|const)\s+json_data\s*=\s*", body)
    if not match:
        raise ValueError("No embedded GoAccess JSON")
    payload, _ = json.JSONDecoder().raw_decode(body[match.end() :])
    if not isinstance(payload, dict):
        raise ValueError("Invalid GoAccess payload")
    general = payload.get("general")
    if not isinstance(general, dict):
        raise ValueError("Missing GoAccess general section")
    generated = None
    try:
        generated = datetime.strptime(
            general.get("date_time", ""), "%Y-%m-%d %H:%M:%S %z"
        ).astimezone(UTC)
    except ValueError, TypeError:
        pass
    summary = {k: count(v) for k, v in general.items() if k in GENERAL}
    for field in ("start_date", "end_date"):
        summary[field] = str(general.get(field, ""))[:60]
    panels = {}
    for name in ("vhosts", "requests", "hosts", "status_codes", "visitors"):
        section = payload.get(name, {})
        rows = section.get("data", []) if isinstance(section, dict) else []
        if not isinstance(rows, list):
            rows = []
        if name == "status_codes":
            # GoAccess nests individual codes under 2xx/3xx/etc. Keep leaves,
            # so group totals and their children cannot be double-counted.
            rows = [
                item
                for row in rows[:500]
                if isinstance(row, dict)
                for item in (
                    row["items"][:500]
                    if isinstance(row.get("items"), list) and row["items"]
                    else [row]
                )
            ]
        result = []
        for row in rows[:500]:
            if not isinstance(row, dict):
                continue
            label = str(row.get("data", ""))[:2048]
            if name == "requests":
                try:
                    label = urlsplit(label).path[:1000] or "/"
                except ValueError:
                    continue
            elif name == "hosts":
                try:
                    label = str(ipaddress.ip_address(label))
                except ValueError:
                    continue
            else:
                label = label[:254]
            result.append(
                {
                    "label": label,
                    "hits": count(row.get("hits")),
                    "visitors": count(row.get("visitors")),
                    "bytes": count(row.get("bytes")),
                    "method": str(row.get("method", ""))[:16],
                }
            )
        panels[name] = result
    return generated, summary, panels
