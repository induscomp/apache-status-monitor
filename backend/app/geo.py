"""Optional local GeoIP only. No external IP lookup requests."""

from functools import lru_cache
from pathlib import Path

import maxminddb

GEO_DIR = Path("/data/geoip")


@lru_cache(maxsize=4096)
def _lookup(address: str, versions: tuple):
    result = {"country": None, "asn": None, "organization": None, "source": "unknown"}
    for name, stamp in versions:
        if stamp is None:
            continue
        try:
            with maxminddb.open_database(GEO_DIR / name) as reader:
                record = reader.get(address) or {}
                if "Country" in name:
                    result["country"] = record.get("country", {}).get("iso_code")
                else:
                    result["asn"] = record.get("autonomous_system_number")
                    result["organization"] = record.get("autonomous_system_organization")
                result["source"] = "local-mmdb"
        except OSError, ValueError, maxminddb.InvalidDatabaseError:
            pass
    return result


def lookup(address):
    versions = []
    for name in ("GeoLite2-Country.mmdb", "GeoLite2-ASN.mmdb"):
        try:
            stamp = (GEO_DIR / name).stat().st_mtime_ns
        except OSError:
            stamp = None
        versions.append((name, stamp))
    return _lookup(address, tuple(versions)).copy()
