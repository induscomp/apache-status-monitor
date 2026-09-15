"""Local country/ASN enrichment. Visitor addresses never leave this installation."""

import ipaddress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import maxminddb

GEO_DIR = Path("/data/geoip")
FILES = (
    "GeoLite2-Country.mmdb",
    "GeoLite2-ASN.mmdb",
    "dbip-country-lite.mmdb",
    "dbip-asn-lite.mmdb",
)


def availability():
    return {
        "country": any((GEO_DIR / n).is_file() for n in FILES if "country" in n.lower()),
        "asn": any((GEO_DIR / n).is_file() for n in FILES if "asn" in n.lower()),
    }


@lru_cache(maxsize=4096)
def _lookup(address, versions):
    result = {
        "country": None,
        "asn": None,
        "organization": None,
        "network": None,
        "source": "unknown",
        "database_at": None,
    }
    for name, stamp in versions:
        if stamp is None:
            continue
        try:
            with maxminddb.open_database(GEO_DIR / name) as reader:
                record, prefix = reader.get_with_prefix_len(address)
                if not record:
                    continue
                if "country" in name.lower():
                    result["country"] = result["country"] or record.get("country", {}).get(
                        "iso_code"
                    )
                elif result["asn"] is None:
                    result["asn"] = record.get("autonomous_system_number")
                    result["organization"] = record.get("autonomous_system_organization")
                    if result["asn"]:
                        result["network"] = str(
                            ipaddress.ip_network(f"{address}/{prefix}", strict=False)
                        )
                        result["database_at"] = datetime.fromtimestamp(
                            reader.metadata().build_epoch, UTC
                        ).isoformat()
                result["source"] = "db-ip-lite" if name.startswith("dbip") else "local-mmdb"
        except OSError, ValueError, maxminddb.InvalidDatabaseError:
            pass
    return result


def lookup(address):
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return {
            "country": None,
            "asn": None,
            "organization": None,
            "network": None,
            "source": "unknown",
        }
    versions = []
    for name in FILES:
        try:
            stamp = (GEO_DIR / name).stat().st_mtime_ns
        except OSError:
            stamp = None
        versions.append((name, stamp))
    return _lookup(address, tuple(versions)).copy()


def enrich(rankings):
    return {**rankings, "ips": [{**row, **lookup(row["ip"])} for row in rankings.get("ips", [])]}
