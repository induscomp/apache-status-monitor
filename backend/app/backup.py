"""Streaming authenticated logical backups. Restore only into an empty migrated database."""

import argparse
import hashlib
import json
import logging
import os
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy import DateTime, delete, func, select, text

from app.config import get_settings
from app.db import session_factory
from app.models import Base, ComponentHeartbeat, now

EXCLUDED = {"auth_sessions", "rate_buckets", "component_heartbeats", "email_deliveries"}
TABLES = [t for t in Base.metadata.sorted_tables if t.name not in EXCLUDED]
BY_NAME = {t.name: t for t in TABLES}
MAX_LINE = 32 * 1024 * 1024


def schema_id():
    return hashlib.sha256(
        json.dumps([(t.name, [(c.name, str(c.type)) for c in t.columns]) for t in TABLES]).encode()
    ).hexdigest()


def key_id():
    return hashlib.sha256(get_settings().encryption_key_file.read_bytes().strip()).hexdigest()


def clean_row(name, row, stamp):
    row = dict(row)
    if "raw_encrypted" in row:
        row["raw_encrypted"] = None
    observed = row.get("observed_at")
    if isinstance(observed, str):
        observed = datetime.fromisoformat(observed)
    if observed and name in {"apache_observations", "mrtg_observations", "server_frames"}:
        if observed < stamp - timedelta(days=90):
            return None
        if observed < stamp - timedelta(days=30):
            for key in ("workers", "details"):
                if key in row:
                    row[key] = None
    if name == "incidents":
        updated = row["updated_at"]
        if isinstance(updated, str):
            updated = datetime.fromisoformat(updated)
        if updated < stamp - timedelta(days=30):
            row["evidence"] = {k: v for k, v in row["evidence"].items() if k != "coincidences"}
    return row


def write_archive(db, path, cipher):
    archive = secrets.token_hex(16)
    count = 0
    stamp = now()
    with path.open("xb") as output:
        os.chmod(path, 0o600)

        def emit(payload):
            nonlocal count
            token = cipher.encrypt(
                json.dumps(
                    {"archive": archive, "sequence": count, **payload},
                    default=lambda v: v.isoformat(),
                    separators=(",", ":"),
                ).encode()
            )
            if len(token) >= MAX_LINE:
                raise ValueError("Backup record too large")
            output.write(token + b"\n")
            count += 1

        emit(
            {
                "kind": "header",
                "format": 1,
                "schema": schema_id(),
                "app_key": key_id(),
                "created_at": stamp.isoformat(),
            }
        )
        for table in TABLES:
            columns = [c for c in table.columns if c.name != "raw_encrypted"]
            for row in db.execute(select(*columns).execution_options(yield_per=10)).mappings():
                cleaned = clean_row(table.name, row, stamp)
                if cleaned is not None:
                    emit({"kind": "row", "table": table.name, "data": cleaned})
        emit({"kind": "end"})
        output.flush()
        os.fsync(output.fileno())


def records(stream, cipher):
    archive = None
    sequence = 0
    ended = False
    while line := stream.readline(MAX_LINE):
        if ended or not line.endswith(b"\n"):
            raise ValueError("Truncated or trailing backup data")
        item = json.loads(cipher.decrypt(line.strip()))
        if sequence == 0:
            if (
                item.get("kind") != "header"
                or item.get("format") != 1
                or item.get("schema") != schema_id()
                or item.get("app_key") != key_id()
            ):
                raise ValueError("Wrong schema or application encryption key")
            archive = item.get("archive")
        if item.get("archive") != archive or item.get("sequence") != sequence:
            raise ValueError("Mixed or reordered backup records")
        kind = item.get("kind")
        if kind == "row":
            table = BY_NAME.get(item.get("table"))
            if (
                table is None
                or not isinstance(item.get("data"), dict)
                or not set(item["data"]) <= set(table.c.keys())
                or "raw_encrypted" in item["data"]
            ):
                raise ValueError("Unexpected backup table or columns")
            yield table, item["data"]
        elif kind == "end":
            ended = True
        elif sequence != 0 or kind != "header":
            raise ValueError("Invalid record type")
        sequence += 1
    if not ended:
        raise ValueError("Backup is incomplete")


def restore(db, path, cipher):
    # First authenticate every record. Keep the same file descriptor for both passes.
    with db.begin_nested(), path.open("rb") as stream:
        for _ in records(stream, cipher):
            pass
        db.execute(text("SELECT pg_advisory_xact_lock(829641702)"))
        for table in Base.metadata.sorted_tables:
            db.execute(text('LOCK TABLE "' + table.name + '" IN ACCESS EXCLUSIVE MODE'))
            if db.scalar(select(func.count()).select_from(table)):
                raise ValueError(
                    "Restore requires an empty migrated database with services stopped"
                )
        stream.seek(0)
        stamp = now()
        for table, data in records(stream, cipher):
            row = clean_row(table.name, data, stamp)
            if row is None:
                continue
            for column in table.columns:
                if isinstance(column.type, DateTime) and row.get(column.name):
                    row[column.name] = datetime.fromisoformat(row[column.name])
            if table.name == "notification_config":
                config = json.loads(get_settings().cipher().decrypt(row["encrypted"].encode()))
                config["enabled"] = False
                row["encrypted"] = (
                    get_settings().cipher().encrypt(json.dumps(config).encode()).decode()
                )
            if table.name == "anomaly_states":
                row["good"] = row["bad"] = 0
            db.execute(table.insert().values(**row))
    # Caller commits only after the authenticated footer and all constraints pass.


def prune(directory):
    import re

    for period, keep, pattern in [
        ("daily", 7, r"backup-daily-\d{4}-\d{2}-\d{2}\.smon"),
        ("weekly", 4, r"backup-weekly-\d{4}-W\d{2}\.smon"),
    ]:
        files = sorted(
            p
            for p in directory.glob(f"backup-{period}-*.smon")
            if re.fullmatch(pattern, p.name) and not p.is_symlink()
        )
        for path in files[:-keep]:
            path.unlink()


def create_daily():
    settings = get_settings()
    directory = settings.backup_directory
    cipher = Fernet(settings.backup_key_file.read_bytes().strip())
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    day = now()
    target = directory / f"backup-daily-{day:%Y-%m-%d}.smon"
    temporary = directory / (".pending-" + secrets.token_hex(12))
    with session_factory()() as lock:
        if not lock.scalar(text("SELECT pg_try_advisory_xact_lock(829641701)")):
            return
        try:
            if not target.exists():
                with session_factory()() as db:
                    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                    db.execute(text("SET TRANSACTION READ ONLY"))
                    write_archive(db, temporary, cipher)
                os.replace(temporary, target)
            with target.open("rb") as stream:
                for _ in records(stream, cipher):
                    pass
            # First successful backup of each ISO week, also recovering missed schedules.
            weekly = directory / f"backup-weekly-{day:%G-W%V}.smon"
            if not weekly.exists():
                shutil.copyfile(target, temporary)
                os.chmod(temporary, 0o600)
                with temporary.open("rb") as copied:
                    os.fsync(copied.fileno())
                os.replace(temporary, weekly)
            prune(directory)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            completed_at = datetime.fromtimestamp(target.stat().st_mtime, UTC)
            heartbeat = lock.get(ComponentHeartbeat, "backup")
            if heartbeat:
                heartbeat.seen_at = completed_at
            else:
                lock.add(ComponentHeartbeat(name="backup", seen_at=completed_at))
            lock.commit()
        finally:
            temporary.unlink(missing_ok=True)


def scheduled():
    try:
        create_daily()
    except Exception as exc:
        logging.getLogger("smon.backup").error(
            json.dumps({"event": "backup_failed", "type": type(exc).__name__})
        )
        # A previously verified file may now be corrupt or inaccessible. Do not
        # continue showing it as available after a failed verification.
        try:
            with session_factory()() as db:
                db.execute(delete(ComponentHeartbeat).where(ComponentHeartbeat.name == "backup"))
                db.commit()
        except Exception:
            logging.getLogger("smon.backup").error('{"event":"backup_health_update_failed"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create", "verify", "restore"])
    parser.add_argument("path", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "create":
            create_daily()
        else:
            if not args.path:
                parser.error("verify/restore requires an archive path")
            cipher = Fernet(get_settings().backup_key_file.read_bytes().strip())
            if args.action == "verify":
                with args.path.open("rb") as stream:
                    for _ in records(stream, cipher):
                        pass
            else:
                with session_factory()() as db:
                    restore(db, args.path, cipher)
                    db.commit()
    except Exception:
        raise SystemExit(
            "Operation failed. Check keys, archive integrity, schema and empty restore target; no secrets are printed."
        ) from None
    print("Backup operation completed successfully.")


if __name__ == "__main__":
    main()
