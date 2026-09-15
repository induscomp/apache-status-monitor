"""Install the monthly DB-IP Lite databases locally, with bounded verified HTTPS downloads."""

import argparse
import gzip
import re
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import maxminddb


def install(directory, release):
    if not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", release):
        raise ValueError("Expected YYYY-MM")
    directory.mkdir(parents=True, exist_ok=True)
    for kind in ("asn", "country"):
        url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{release}.mmdb.gz"
        with tempfile.TemporaryDirectory(dir=directory) as work:
            compressed = Path(work) / "download.gz"
            request = urllib.request.Request(
                url, headers={"User-Agent": "Apache-Status-Monitor/0.3"}
            )
            with (
                urllib.request.urlopen(request, timeout=30) as response,  # noqa: S310 — fixed HTTPS host and validated release
                compressed.open("wb") as output,
            ):
                if response.url != url:
                    raise ValueError("Unexpected redirect")
                size = 0
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > 32 * 1024 * 1024:
                        raise ValueError("Download too large")
                    output.write(chunk)
            target = Path(work) / "database.mmdb"
            with gzip.open(compressed, "rb") as source, target.open("wb") as output:
                size = 0
                while chunk := source.read(65536):
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise ValueError("Database too large")
                    output.write(chunk)
            with maxminddb.open_database(target) as reader:
                if reader.metadata().node_count < 1:
                    raise ValueError("Empty database")
            target.chmod(0o644)
            target.replace(directory / f"dbip-{kind}-lite.mmdb")
        print(f"DB-IP Lite {kind}: {release} installed; attribution https://db-ip.com (CC BY 4.0)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--release", default=datetime.now(UTC).strftime("%Y-%m"))
    args = parser.parse_args()
    install(args.directory, args.release)
